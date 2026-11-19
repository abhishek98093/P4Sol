"""
controller.py — ARP Flood Detection Controller
================================================
Two subsystems:

  (A) Passive monitoring — parses 45-byte P4 CPU-header digests, computes
      15 ML features per 1-second window, writes CSV, prints [WIN] +
      [TOP_SRC] + [TOP_PORT] lines.

  (B) Runtime detection + port blocking — loads a model (.pkl), predicts
      attack/normal per window, and when attack is predicted AND the top
      host-port share is high, installs a port block on the source edge
      switch via simple_switch_CLI. Auto-expires after 15 s.

Snapshot-pattern architecture (v4):
  The ticker thread captures a snapshot of the current window under the
  ingest lock in microseconds, then does ALL heavy work (CSV write, log
  emission, model inference, CLI subprocess for block install) OUTSIDE
  the lock.

  Sockets use SO_RCVBUFFORCE (requires CAP_NET_ADMIN) to bypass
  net.core.rmem_max. Startup log prints the ACTUAL kernel-accepted buffer
  per interface so you can verify it was applied.

  Per-interface drop tracking: [WIN] log shows a breakdown of kernel drops
  by interface in brackets, e.g. drops=15 [s1-cpu1=12 s11-cpu1=3].

Top-port selection (v4 — critical fix):
  In request-reply floods, the attacker emits ARP requests (op=1) and the
  victim emits ARP replies (op=2). Both have nearly equal packet counts,
  so picking the top port by raw packet count picks the wrong side ~50%
  of the time — blocking the victim instead of the attacker.

  The fix: pick the top port by REQUEST count (op=1). The attacker is
  the only port emitting requests in a request flood. For pure reply
  floods (poison/mitm/gateway), no requests exist, so fall back to raw
  packet count — which is correct because only the attacker emits replies.

  top_port_share then measures the attacker's fraction of REQUESTS, so
  the gate (>=0.30) passes for a single attacker (share=1.0) and for
  3 attackers (share=0.33), but fails for distributed 5+ attackers
  (share=0.20 — correct: those need multi-window cascading).

CSV columns (24 total):
  timestamp (1)
  15 ML features:
    arp_rate, request_reply_imbalance,
    src_ip_entropy, unique_src_ip_count,
    src_mac_entropy, target_ip_entropy, unique_target_ip_count,
    broadcast_fraction, gratuitous_fraction,
    self_mac_mismatch_count, delta_arp_rate,
    new_ip_ratio, cross_switch_spread,
    top_port_share, unique_host_ports
  Block-target metadata:
    top_sw_id, top_ingress_port, top_port_composite, port_pkts_raw
  Diagnostics:
    digests_received, top_src_ip, top_src_ip_share
  Label:
    label (0 = normal, 1 = attack)
"""

import os, sys, time, struct, math, socket, select, subprocess, shutil
import threading, collections, csv, logging, argparse, signal
from datetime import datetime

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/controller.log"),
    ]
)
log = logging.getLogger("ctrl")

# ── Config ────────────────────────────────────────────────────────────────────
WINDOW_SEC      = 1
CPU_REASON      = 0xAA
_BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_PATH = os.path.join(_BASE, "dataset", "arp_dataset_new.csv")

IFACE_RETRY_SEC = 2
ETH_P_ALL       = 0x0003
RECV_BUF_SIZE   = 65535
SO_RCVBUF_BYTES = 64 * 1024 * 1024          # 64 MB — kernel doubles to 128 MB
SHUTDOWN        = threading.Event()

SO_RCVBUFFORCE  = 33                        # SO_RCVBUF | SO_FORCE

SOL_PACKET        = 263
PACKET_STATISTICS = 6
TPACKET_STATS_FMT = "II"
TPACKET_STATS_LEN = struct.calcsize(TPACKET_STATS_FMT)

EDGE_SWITCHES       = {1, 2, 3, 4}
HOST_PORT_MAX       = 15
THRIFT_PORT         = lambda sw: 9090 + (sw - 1) * 10

FEATURE_COLUMNS = [
    "arp_rate", "request_reply_imbalance",
    "src_ip_entropy", "unique_src_ip_count",
    "src_mac_entropy", "target_ip_entropy", "unique_target_ip_count",
    "broadcast_fraction", "gratuitous_fraction",
    "self_mac_mismatch_count", "delta_arp_rate",
    "new_ip_ratio", "cross_switch_spread",
    "top_port_share", "unique_host_ports",
]

CPU_FMT  = "!BB H 4s 6s 4s H IIIII BI"
CPU_SIZE = struct.calcsize(CPU_FMT)
assert CPU_SIZE == 45, f"CPU_SIZE is {CPU_SIZE}, expected 45"


class CpuHeader:
    __slots__ = [
        "switch_id", "ingress_port",
        "sender_ip", "sender_mac", "target_ip", "opcode",
        "reg_total", "reg_req", "reg_rep",
        "reg_grat", "reg_bcast", "reg_ctr",
        "reg_self_mismatch",
    ]

    @classmethod
    def parse(cls, raw: bytes):
        if len(raw) < CPU_SIZE:
            return None
        if raw[0] != CPU_REASON:
            return None
        try:
            f = struct.unpack_from(CPU_FMT, raw, 0)
        except struct.error:
            return None
        o = cls()
        o.switch_id         = f[1]
        o.ingress_port      = (f[2] & 0xFF80) >> 7
        o.sender_ip         = socket.inet_ntoa(f[3])
        o.sender_mac        = ":".join(f"{b:02x}" for b in f[4])
        o.target_ip         = socket.inet_ntoa(f[5])
        o.opcode            = f[6]
        o.reg_total         = f[7]
        o.reg_req           = f[8]
        o.reg_rep           = f[9]
        o.reg_grat          = f[10]
        o.reg_bcast         = f[11]
        o.reg_ctr           = f[12]
        o.reg_self_mismatch = f[13]
        return o


def _read_packet_drops(sock) -> int:
    try:
        data = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, TPACKET_STATS_LEN)
        _tp_packets, tp_drops = struct.unpack(TPACKET_STATS_FMT, data)
        return tp_drops
    except OSError:
        return 0


# ══════════════════════════════════════════════════════════════════════════════
#  PORT-BLOCK THREAD
# ══════════════════════════════════════════════════════════════════════════════

class PortBlocker:
    """Installs/removes tbl_block_port entries; auto-expires after hold_sec."""

    def __init__(self, hold_sec=15.0, cli_binary="simple_switch_CLI", timeout=5):
        self.hold_sec  = hold_sec
        self.cli       = cli_binary
        self.timeout   = timeout
        self.installed = {}
        self.lock      = threading.Lock()

        if shutil.which(cli_binary) is None:
            log.warning(f"[PORTBLK] '{cli_binary}' not found in PATH — "
                        f"port blocking will be a no-op")

    def _run_cli(self, sw, command: str) -> str:
        thrift = THRIFT_PORT(sw)
        try:
            r = subprocess.run(
                [self.cli, "--thrift-port", str(thrift)],
                input=command + "\n",
                capture_output=True, text=True, timeout=self.timeout,
            )
        except FileNotFoundError:
            raise RuntimeError(f"{self.cli} not found")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"CLI timeout sw={sw} port={thrift}")
        if r.returncode != 0:
            raise RuntimeError(f"CLI rc={r.returncode}: "
                               f"{r.stderr.strip() or r.stdout.strip()}")
        return r.stdout

    @staticmethod
    def _parse_handle(stdout: str):
        for line in stdout.splitlines():
            if "handle" in line.lower():
                nums = [t.strip("(),") for t in line.split()
                        if t.strip("(),").isdigit()]
                if nums:
                    return int(nums[-1])
        return None

    def block(self, sw: int, port: int, share: float):
        key = (sw, port)
        with self.lock:
            if key in self.installed:
                handle, _ = self.installed[key]
                self.installed[key] = (handle, time.time() + self.hold_sec)
                return
        try:
            out = self._run_cli(sw, f"table_add tbl_block_port block_source {port} =>")
            handle = self._parse_handle(out)
            with self.lock:
                self.installed[key] = (handle, time.time() + self.hold_sec)
            log.info(f"[PORTBLK] BLOCK sw={sw} port={port} share={share:.2f} "
                     f"handle={handle} hold={self.hold_sec:.0f}s")
        except Exception as e:
            log.warning(f"[PORTBLK] install sw={sw} port={port} failed: {e}")

    def expire_loop(self):
        while not SHUTDOWN.is_set():
            now = time.time()
            to_remove = []
            with self.lock:
                for key, (handle, exp) in self.installed.items():
                    if now >= exp:
                        to_remove.append((key, handle))
            for (sw, port), handle in to_remove:
                try:
                    self._run_cli(sw, f"table_delete tbl_block_port {handle}")
                    log.info(f"[PORTBLK] UNBLOCK sw={sw} port={port} handle={handle}")
                except Exception as e:
                    log.warning(f"[PORTBLK] unblock sw={sw} port={port} failed: {e}")
                with self.lock:
                    self.installed.pop((sw, port), None)
            SHUTDOWN.wait(0.5)


# ══════════════════════════════════════════════════════════════════════════════
#  WINDOW AGGREGATOR
# ══════════════════════════════════════════════════════════════════════════════

class WindowAggregator:
    def __init__(self, window_sec, dataset_path, label_mode,
                 model=None, predict_threshold=0.70,
                 port_share_threshold=0.30, port_pkts_threshold=15,
                 blocker: PortBlocker = None):
        self.window_sec         = window_sec
        self.dataset_path       = dataset_path
        self.label_mode         = label_mode
        self.lock               = threading.Lock()
        self._processing_lock   = threading.Lock()
        self._model             = model
        self._predict_threshold = predict_threshold
        self._port_share_thr    = port_share_threshold
        self._port_pkts_thr     = port_pkts_threshold
        self._blocker           = blocker

        self._prev_src_ips  = set()
        self._prev_arp_rate = 0.0
        self._window_seq    = 0

        self._reset()
        self._init_csv()

    def _reset(self):
        self.agg_total    = 0
        self.agg_req      = 0
        self.agg_rep      = 0
        self.agg_grat     = 0
        self.agg_bcast    = 0
        self.agg_selfmm   = 0
        self.sip_list     = []
        self.smac_list    = []
        self.tip_list     = []
        self.swid_list    = []
        self.port_pktcounts = collections.Counter()
        self.port_reqcounts = collections.Counter()   # NEW: requests per (sw,port)
        self.port_digests   = collections.Counter()
        self.n_packetin   = 0
        self.window_drops = 0
        self._drops_by_iface = collections.Counter()
        self.win_start    = time.time()

    def _init_csv(self):
        os.makedirs(os.path.dirname(self.dataset_path), exist_ok=True)
        write_hdr = not os.path.exists(self.dataset_path)
        self._f = open(self.dataset_path, "a", newline="")
        self._w = csv.writer(self._f)
        if write_hdr:
            self._w.writerow([
                "timestamp",
                "arp_rate", "request_reply_imbalance",
                "src_ip_entropy", "unique_src_ip_count",
                "src_mac_entropy", "target_ip_entropy",
                "unique_target_ip_count",
                "broadcast_fraction", "gratuitous_fraction",
                "self_mac_mismatch_count", "delta_arp_rate",
                "new_ip_ratio", "cross_switch_spread",
                "top_port_share", "unique_host_ports",
                "top_sw_id", "top_ingress_port", "top_port_composite",
                "port_pkts_raw",
                "digests_received", "top_src_ip",
                "top_src_ip_share",
                "label",
            ])
            self._f.flush()
        log.info(f"[CSV] {self.dataset_path}")

    def ingest(self, h: CpuHeader):
        with self.lock:
            self.agg_total  += h.reg_total
            self.agg_req    += h.reg_req
            self.agg_rep    += h.reg_rep
            self.agg_grat   += h.reg_grat
            self.agg_bcast  += h.reg_bcast
            self.agg_selfmm += h.reg_self_mismatch
            self.sip_list.append(h.sender_ip)
            self.smac_list.append(h.sender_mac)
            self.tip_list.append(h.target_ip)
            self.swid_list.append(h.switch_id)
            self.n_packetin += 1

            if h.switch_id in EDGE_SWITCHES and h.ingress_port < HOST_PORT_MAX:
                key = (h.switch_id, h.ingress_port)
                self.port_pktcounts[key] += h.reg_total
                self.port_digests[key]   += 1
                if h.opcode == 1:                     # NEW: op=1 = ARP request
                    self.port_reqcounts[key] += h.reg_total

    def note_drop(self, n=1, iface="?"):
        if n <= 0:
            return
        with self.lock:
            self.window_drops += n
            self._drops_by_iface[iface] += n

    def tick(self):
        snap = None
        with self.lock:
            if time.time() - self.win_start >= self.window_sec:
                snap = self._snapshot_and_reset()
        if snap is None:
            return

        if not self._processing_lock.acquire(blocking=False):
            log.warning(f"[WIN] seq={snap['seq']} skipped — "
                        f"previous snapshot still processing")
            return
        try:
            self._process_snapshot(snap)
        except Exception as e:
            log.error(f"[WIN] seq={snap['seq']} processing failed: {e}")
        finally:
            self._processing_lock.release()

    def _snapshot_and_reset(self):
        self._window_seq += 1
        elapsed  = max(time.time() - self.win_start, 0.001)
        arp_rate = round(self.agg_total / elapsed, 4)
        usip     = set(self.sip_list)

        snap = {
            'seq':              self._window_seq,
            'elapsed':          elapsed,
            'win_start':        self.win_start,
            'arp_rate':         arp_rate,
            'prev_arp_rate':    self._prev_arp_rate,
            'prev_src_ips':     self._prev_src_ips,
            'usip':             usip,
            'agg_total':        self.agg_total,
            'agg_req':          self.agg_req,
            'agg_rep':          self.agg_rep,
            'agg_grat':         self.agg_grat,
            'agg_bcast':        self.agg_bcast,
            'agg_selfmm':       self.agg_selfmm,
            'sip_list':         list(self.sip_list),
            'smac_list':        list(self.smac_list),
            'tip_list':         list(self.tip_list),
            'swid_list':        list(self.swid_list),
            'port_pktcounts':   dict(self.port_pktcounts),
            'port_reqcounts':   dict(self.port_reqcounts),   # NEW
            'n_packetin':       self.n_packetin,
            'window_drops':     self.window_drops,
            'drops_by_iface':   dict(self._drops_by_iface),
        }

        self._prev_src_ips  = usip
        self._prev_arp_rate = arp_rate
        self._reset()
        return snap

    def _process_snapshot(self, snap):
        raw_total = snap['agg_total']
        raw_req   = snap['agg_req']
        raw_rep   = snap['agg_rep']
        raw_grat  = snap['agg_grat']
        raw_bcast = snap['agg_bcast']
        raw_selfmm = snap['agg_selfmm']

        arp_rate = snap['arp_rate']

        request_reply_imbalance = round(
            (raw_req - raw_rep) / (raw_req + raw_rep + 1), 4)

        src_ip_entropy    = round(self._entropy(snap['sip_list']), 4)
        src_mac_entropy   = round(self._entropy(snap['smac_list']), 4)
        target_ip_entropy = round(self._entropy(snap['tip_list']), 4)

        usip = snap['usip']
        unique_src_ip_count    = len(usip)
        unique_target_ip_count = len(set(snap['tip_list']))

        broadcast_fraction   = round(raw_bcast / (raw_total + 1), 4)
        gratuitous_fraction  = round(raw_grat / (raw_total + 1), 4)
        self_mac_mismatch_count = raw_selfmm
        delta_arp_rate       = round(arp_rate - snap['prev_arp_rate'], 4)

        if usip:
            new_ip_ratio = round(
                len(usip - snap['prev_src_ips']) / len(usip), 4)
        else:
            new_ip_ratio = 0.0
        cross_switch_spread = len(set(snap['swid_list']))

        # ── Top-port selection (v4 fix) ────────────────────────────────
        # Request floods: pick attacker by highest request count.
        # Reply floods:   fall back to highest packet count.
        port_pktcounts  = snap['port_pktcounts']
        port_reqcounts  = snap.get('port_reqcounts', {})
        total_host_pkts = sum(port_pktcounts.values())
        total_host_reqs = sum(port_reqcounts.values())

        if port_pktcounts and total_host_pkts > 0:
            if port_reqcounts and total_host_reqs > 0:
                # Request flood — attacker is the one emitting op=1
                (top_sw, top_port), top_reqs = max(
                    port_reqcounts.items(), key=lambda kv: kv[1])
                top_port_share = round(top_reqs / total_host_reqs, 4)
                top_pkts       = port_pktcounts.get((top_sw, top_port), 0)
            else:
                # Reply flood (poison/mitm/gateway) — no requests; pick by packets
                (top_sw, top_port), top_pkts = max(
                    port_pktcounts.items(), key=lambda kv: kv[1])
                top_port_share = round(top_pkts / total_host_pkts, 4)
            unique_host_ports = len(port_pktcounts)
        else:
            top_sw = top_port = top_pkts = 0
            top_port_share    = 0.0
            unique_host_ports = 0

        top_port_composite = (top_sw << 8) | top_port

        digests_received  = snap['n_packetin']
        drops_this_window = snap['window_drops']
        drops_by_iface    = snap['drops_by_iface']

        # Top source IP
        if snap['sip_list']:
            ctr = collections.Counter(snap['sip_list'])
            top_src_ip, top_count = ctr.most_common(1)[0]
            top_share = round(top_count / len(snap['sip_list']), 4)
        else:
            top_src_ip, top_count, top_share = "-", 0, 0.0

        label = 1 if self.label_mode == "attack" else 0
        ts    = datetime.fromtimestamp(snap['win_start']).isoformat(
                    timespec="seconds")

        self._w.writerow([
            ts,
            arp_rate, request_reply_imbalance,
            src_ip_entropy, unique_src_ip_count,
            src_mac_entropy, target_ip_entropy, unique_target_ip_count,
            broadcast_fraction, gratuitous_fraction,
            self_mac_mismatch_count, delta_arp_rate,
            new_ip_ratio, cross_switch_spread,
            top_port_share, unique_host_ports,
            top_sw, top_port, top_port_composite,
            top_pkts,
            digests_received, top_src_ip,
            top_share,
            label,
        ])
        self._f.flush()

        drops_str = " ".join(f"{k}={v}" for k, v in sorted(drops_by_iface.items())
                             if v > 0)

        log.info(
            f"[WIN] {ts} | seq={snap['seq']} "
            f"digests={digests_received:4d} "
            f"total={raw_total:6d} req={raw_req:6d} rep={raw_rep:6d} "
            f"grat={raw_grat:5d} bcast={raw_bcast:6d} selfmm={raw_selfmm:3d} "
            f"drops={drops_this_window:3d} [{drops_str or '-'}] | "
            f"rate={arp_rate:8.2f}pps imb={request_reply_imbalance:+.3f} "
            f"H_src={src_ip_entropy:5.3f} uniq_src={unique_src_ip_count:3d} "
            f"H_mac={src_mac_entropy:5.3f} H_tgt={target_ip_entropy:5.3f} "
            f"uniq_tgt={unique_target_ip_count:3d} | "
            f"bcast%={broadcast_fraction:.3f} grat%={gratuitous_fraction:.3f} "
            f"drate={delta_arp_rate:+9.2f} newip={new_ip_ratio:.3f} "
            f"spread={cross_switch_spread} | "
            f"top_src={top_src_ip} ({top_share*100:.1f}%, {top_count}pkts) | "
            f"top_port=s{top_sw}/p{top_port} "
            f"share={top_port_share*100:.1f}% uniq_ports={unique_host_ports} | "
            f"label={'ATTACK' if label else 'normal'}"
        )

        if top_count > 0:
            log.info(f"[TOP_SRC] {ts} | {top_src_ip} "
                     f"share={top_share*100:.1f}% count={top_count}")

        if top_pkts > 0:
            log.info(f"[TOP_PORT] {ts} | s{top_sw} port {top_port} "
                     f"composite=0x{top_port_composite:04x} "
                     f"share={top_port_share*100:.1f}% "
                     f"pkts={top_pkts} uniq_ports={unique_host_ports}")

        if self._model is not None:
            feat_vec = [
                arp_rate, request_reply_imbalance,
                src_ip_entropy, unique_src_ip_count,
                src_mac_entropy, target_ip_entropy, unique_target_ip_count,
                broadcast_fraction, gratuitous_fraction,
                self_mac_mismatch_count, delta_arp_rate,
                new_ip_ratio, cross_switch_spread,
                top_port_share, unique_host_ports,
            ]
            try:
                proba = float(self._model.predict_proba([feat_vec])[0][1])
            except Exception as e:
                log.warning(f"[PREDICT] model inference failed: {e}")
                proba = -1.0

            if proba >= 0:
                is_attack  = proba >= self._predict_threshold
                can_block  = (top_port_share >= self._port_share_thr
                              and top_pkts >= self._port_pkts_thr)
                will_block = is_attack and can_block
                log.info(
                    f"[PREDICT] {ts} | prob_attack={proba:.3f} "
                    f"is_attack={is_attack} top_port_share={top_port_share:.2f} "
                    f"port_pkts={top_pkts} will_block={will_block}"
                )
                if will_block and self._blocker is not None:
                    self._blocker.block(top_sw, top_port, top_port_share)

    @staticmethod
    def _entropy(items):
        if not items:
            return 0.0
        c = collections.Counter(items)
        t = len(items)
        return -sum((v / t) * math.log2(v / t) for v in c.values())

    def set_label(self, mode):
        with self.lock:
            self.label_mode = mode
        log.info(f"[LABEL] → {mode}")

    def close(self):
        snap = None
        with self.lock:
            if self.n_packetin > 0:
                snap = self._snapshot_and_reset()
        if snap is not None:
            with self._processing_lock:
                try:
                    self._process_snapshot(snap)
                except Exception as e:
                    log.error(f"[WIN] final flush failed: {e}")
        self._f.close()
        log.info("[CTRL] CSV closed.")


# ══════════════════════════════════════════════════════════════════════════════
#  SNIFFER
# ══════════════════════════════════════════════════════════════════════════════

_agg: WindowAggregator = None


def _open_raw_socket(iface: str):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_ALL))
    except OSError as e:
        log.debug(f"[SNIFF] {iface} socket failed errno={e.errno}: {e}")
        return None

    actual_kb = 0
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, SO_RCVBUF_BYTES)
        actual_kb = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) // 1024
        log.info(f"[SNIFF] {iface} buffer=FORCE {actual_kb//1024} MB "
                 f"(requested {SO_RCVBUF_BYTES//1024//1024} MB)")
    except (OSError, PermissionError) as e:
        log.warning(f"[SNIFF] {iface} SO_RCVBUFFORCE failed ({e}) — "
                    f"falling back to SO_RCVBUF")
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_BYTES)
            actual_kb = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) // 1024
            log.info(f"[SNIFF] {iface} buffer=SO_RCVBUF {actual_kb//1024} MB "
                     f"(requested {SO_RCVBUF_BYTES//1024//1024} MB)")
        except OSError as e2:
            log.warning(f"[SNIFF] {iface} SO_RCVBUF also failed: {e2}")

    if actual_kb < 4096:
        log.warning(f"[SNIFF] {iface} kernel buffer is only {actual_kb} KB. "
                    f"Check: sysctl net.core.rmem_max "
                    f"(should be 134217728) and that python runs as root "
                    f"(CAP_NET_ADMIN). Drops are likely.")

    try:
        s.bind((iface, ETH_P_ALL))
        s.setblocking(False)
        return s
    except OSError as e:
        log.debug(f"[SNIFF] {iface} bind failed errno={e.errno}: {e}")
        try: s.close()
        except Exception: pass
        return None


def _sniff_thread(iface: str):
    announced_wait = False
    while not SHUTDOWN.is_set():
        sock = _open_raw_socket(iface)
        if sock is None:
            if not announced_wait:
                log.info(f"[SNIFF] Waiting for {iface} to become available...")
                announced_wait = True
            if SHUTDOWN.wait(IFACE_RETRY_SEC):
                return
            continue
        announced_wait = False
        log.info(f"[SNIFF] Capturing on {iface}")
        _read_packet_drops(sock)
        try:
            while not SHUTDOWN.is_set():
                r, _, _ = select.select([sock], [], [], 0.5)
                if not r:
                    drops = _read_packet_drops(sock)
                    if drops:
                        _agg.note_drop(drops, iface)
                    continue
                while True:
                    try:
                        raw, _addr = sock.recvfrom(RECV_BUF_SIZE)
                    except BlockingIOError:
                        break
                    except OSError:
                        raise
                    if not raw:
                        continue
                    h = CpuHeader.parse(raw)
                    if h is not None:
                        _agg.ingest(h)
                drops = _read_packet_drops(sock)
                if drops:
                    _agg.note_drop(drops, iface)
        except OSError as e:
            log.warning(f"[SNIFF] {iface} lost (errno={e.errno}): {e}. Reconnecting...")
        except Exception as e:
            log.warning(f"[SNIFF] {iface} error: {e}. Reconnecting...")
        finally:
            try: sock.close()
            except Exception: pass
        if SHUTDOWN.wait(IFACE_RETRY_SEC):
            return


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def _load_model(path):
    if not path:
        return None
    if not os.path.exists(path):
        log.warning(f"[MODEL] {path} not found — running without model")
        return None
    try:
        import joblib
        m = joblib.load(path)
        log.info(f"[MODEL] Loaded {path} ({type(m).__name__})")
        return m
    except Exception:
        try:
            import pickle
            with open(path, "rb") as f:
                m = pickle.load(f)
            log.info(f"[MODEL] Loaded {path} via pickle ({type(m).__name__})")
            return m
        except Exception as e:
            log.error(f"[MODEL] Failed to load {path}: {e}")
            return None


def main():
    global _agg

    ap = argparse.ArgumentParser()
    ap.add_argument("--interfaces", "-i", nargs="+", required=True)
    ap.add_argument("--window",  "-w", type=int, default=WINDOW_SEC)
    ap.add_argument("--label",   "-l", choices=["normal","attack"], default="normal")
    ap.add_argument("--dataset", "-d", default=DATASET_PATH)
    ap.add_argument("--model",   "-m", default=None)
    ap.add_argument("--predict-threshold",    type=float, default=0.70)
    ap.add_argument("--port-share-threshold", type=float, default=0.30)
    ap.add_argument("--port-pkts-threshold",  type=int,   default=15)
    ap.add_argument("--block-hold",           type=float, default=15.0)
    args = ap.parse_args()

    if os.geteuid() != 0:
        log.error("needs root (AF_PACKET requires CAP_NET_RAW)")
        sys.exit(1)

    log.info("=" * 72)
    log.info("  ARP Flood Detection Controller (snapshot-pattern v4 — "
             "request-count top-port)")
    log.info(f"  Interfaces  : {args.interfaces}")
    log.info(f"  Window      : {args.window}s")
    log.info(f"  Label       : {args.label}")
    log.info(f"  Dataset     : {args.dataset}")
    log.info(f"  Model       : {args.model or '(none — monitoring only)'}")
    log.info(f"  Predict thr : {args.predict_threshold}")
    log.info(f"  Port share  : {args.port_share_threshold}")
    log.info(f"  Port pkts   : {args.port_pkts_threshold}")
    log.info(f"  Block hold  : {args.block_hold}s")
    log.info(f"  CPU_SIZE    : {CPU_SIZE} bytes")
    log.info(f"  Buffer req  : {SO_RCVBUF_BYTES//1024//1024} MB "
             f"(via SO_RCVBUFFORCE)")
    log.info("=" * 72)

    model   = _load_model(args.model)
    blocker = PortBlocker(hold_sec=args.block_hold) if model else None

    _agg = WindowAggregator(
        args.window, args.dataset, args.label,
        model=model,
        predict_threshold=args.predict_threshold,
        port_share_threshold=args.port_share_threshold,
        port_pkts_threshold=args.port_pkts_threshold,
        blocker=blocker,
    )

    threads = []
    for iface in args.interfaces:
        t = threading.Thread(target=_sniff_thread, args=(iface,),
                             name=f"sniff-{iface}", daemon=True)
        t.start()
        threads.append(t)

    def _ticker():
        while not SHUTDOWN.is_set():
            if SHUTDOWN.wait(0.5):
                return
            _agg.tick()
    threading.Thread(target=_ticker, name="ticker", daemon=True).start()

    if blocker is not None:
        threading.Thread(target=blocker.expire_loop,
                         name="port-block-expire", daemon=True).start()

    def _toggle(sig, frame):
        _agg.set_label("attack" if _agg.label_mode == "normal" else "normal")
    signal.signal(signal.SIGUSR1, _toggle)

    log.info(f"[CTRL] PID={os.getpid()}  Running. Ctrl+C to stop.")
    try:
        while not SHUTDOWN.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("[CTRL] Shutting down...")
    finally:
        SHUTDOWN.set()
        for t in threads:
            t.join(timeout=1.0)
        _agg.close()


if __name__ == "__main__":
    main()

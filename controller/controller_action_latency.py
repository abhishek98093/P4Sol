"""
controller_action_latency.py — ARP Flood Detection Controller (v6)
====================================================================
Identical to controller/controller.py (v5) plus action-latency
instrumentation. Does NOT replace the original file.

NEW (additive only):
    - Measures detection + mitigation latency in milliseconds.
    - Appends to `action_latency.csv` (never overwrites between runs).
    - Only writes a row when the model flags `is_attack=True`.
    - Columns:
        model_latency_ms   = window_end → prediction_done
        rule_install_ms    = prediction_done → rule_installed (pure CLI)
        total_latency_ms   = window_end → rule_installed (end-to-end)
        install_status     = ok | blocked | no_port | failed | skipped
    - `--latency-csv PATH` overrides the default path
      (default: <project_root>/action_latency.csv, append mode).

USAGE:
    sudo python3 controller/controller_action_latency.py \\
        --interfaces s1-cpu1 s2-cpu1 s3-cpu1 s4-cpu1 s11-cpu1 \\
        --model models/arp_rf.pkl \\
        --predict-threshold 0.90 \\
        --port-share-threshold 0.30 \\
        --port-pkts-threshold 15 \\
        --observation-sec 3600 \\
        --base-penalty-sec 5 \\
        --max-penalty-sec 900 \\
        [--latency-csv action_latency.csv]
"""

import os, sys, time, struct, math, socket, select, subprocess, shutil, csv
import threading, collections, logging, argparse, signal
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/controller_action_latency.log"),
    ]
)
log = logging.getLogger("ctrl")

# ── Config (identical to v5) ──────────────────────────────────────────
WINDOW_SEC      = 1
CPU_REASON      = 0xAA
IFACE_RETRY_SEC = 2
ETH_P_ALL       = 0x0003
RECV_BUF_SIZE   = 65535
SO_RCVBUF_BYTES = 64 * 1024 * 1024
SO_RCVBUFFORCE  = 33
SHUTDOWN        = threading.Event()

SOL_PACKET        = 263
PACKET_STATISTICS = 6
TPACKET_STATS_FMT = "II"
TPACKET_STATS_LEN = struct.calcsize(TPACKET_STATS_FMT)

EDGE_SWITCHES = {1, 2, 3, 4}
HOST_PORT_MAX = 15
THRIFT_PORT   = lambda sw: 9090 + (sw - 1) * 10

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
assert CPU_SIZE == 45

# ── Latency CSV schema ───────────────────────────────────────────────
LATENCY_FIELDS = [
    "timestamp", "window_start", "window_end", "seq",
    "arp_rate", "prob_attack", "is_attack", "can_block", "will_block",
    "top_sw", "top_port", "share", "top_pkts",
    "model_latency_ms", "rule_install_ms", "total_latency_ms",
    "install_status", "block_duration_sec", "block_count",
]


def _default_latency_csv():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "action_latency.csv"))


# ══════════════════════════════════════════════════════════════════════
#  LatencyRecorder — append-mode, thread-safe
# ══════════════════════════════════════════════════════════════════════
class LatencyRecorder:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        new = not os.path.exists(path)
        self.fh = open(path, "a", newline="")
        self.w  = csv.DictWriter(self.fh, fieldnames=LATENCY_FIELDS)
        if new:
            self.w.writeheader()
            self.fh.flush()

    def write(self, row):
        with self.lock:
            try:
                self.w.writerow(row)
                self.fh.flush()
            except Exception as e:
                log.warning(f"[LATENCY] CSV write failed: {e}")

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  CpuHeader (identical to v5)
# ══════════════════════════════════════════════════════════════════════
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
        if len(raw) < CPU_SIZE or raw[0] != CPU_REASON:
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


# ══════════════════════════════════════════════════════════════════════
#  Defaulter (identical to v5)
# ══════════════════════════════════════════════════════════════════════
class Defaulter:
    __slots__ = ("sw", "port", "block_count",
                 "block_until", "observation_until", "first_seen")

    def __init__(self, sw, port, now=None):
        now = now if now is not None else time.time()
        self.sw = sw
        self.port = port
        self.block_count = 0
        self.block_until = 0.0
        self.observation_until = 0.0
        self.first_seen = now

    def is_blocked(self, now):   return now < self.block_until
    def is_observed(self, now):  return now < self.observation_until

    def penalty(self, base_sec, max_sec):
        n = max(self.block_count, 1)
        return min(base_sec * (2 ** (n - 1)), max_sec)

    def register_attack(self, now, base_sec, max_sec, observation_sec):
        self.block_count += 1
        p = self.penalty(base_sec, max_sec)
        self.block_until = now + p
        self.observation_until = self.block_until + observation_sec
        return p


# ══════════════════════════════════════════════════════════════════════
#  PortBlocker (identical to v5)
# ══════════════════════════════════════════════════════════════════════
class PortBlocker:
    def __init__(self, cli_binary="simple_switch_CLI", timeout=5):
        self.cli       = cli_binary
        self.timeout   = timeout
        self.installed = {}
        self.lock      = threading.Lock()
        if shutil.which(cli_binary) is None:
            log.warning(f"[BLOCK] '{cli_binary}' not in PATH — blocking is a no-op")

    def _run_cli(self, sw, command):
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
            raise RuntimeError(f"CLI timeout sw={sw}")
        if r.returncode != 0:
            raise RuntimeError(f"CLI rc={r.returncode}: "
                               f"{r.stderr.strip() or r.stdout.strip()}")
        return r.stdout

    @staticmethod
    def _parse_handle(stdout):
        for line in stdout.splitlines():
            if "handle" in line.lower():
                nums = [t.strip("(),") for t in line.split()
                        if t.strip("(),").isdigit()]
                if nums:
                    return int(nums[-1])
        return None

    def install(self, sw, port, seconds, reason=""):
        key = (sw, port)
        with self.lock:
            if key in self.installed:
                return None
        try:
            out = self._run_cli(sw, f"table_add tbl_block_port block_source {port} =>")
            handle = self._parse_handle(out)
            with self.lock:
                self.installed[key] = (handle, time.time() + seconds)
            log.info(f"[BLOCK] sw={sw} port={port} duration={seconds:.0f}s "
                     f"handle={handle} ({reason})")
            return handle
        except Exception as e:
            log.warning(f"[BLOCK] install failed sw={sw} port={port}: {e}")
            return None

    def remove(self, sw, port):
        key = (sw, port)
        with self.lock:
            entry = self.installed.pop(key, None)
        if not entry:
            return
        handle, _ = entry
        try:
            self._run_cli(sw, f"table_delete tbl_block_port {handle}")
            log.info(f"[UNBLOCK] sw={sw} port={port} handle={handle}")
        except Exception as e:
            log.warning(f"[UNBLOCK] failed sw={sw} port={port}: {e}")

    def expire_loop(self):
        while not SHUTDOWN.is_set():
            now = time.time()
            with self.lock:
                expired = [(k, v[0]) for k, v in self.installed.items()
                           if now >= v[1]]
            for (sw, port), handle in expired:
                try:
                    self._run_cli(sw, f"table_delete tbl_block_port {handle}")
                    with self.lock:
                        self.installed.pop((sw, port), None)
                    log.info(f"[UNBLOCK] sw={sw} port={port} handle={handle} (expired)")
                except Exception as e:
                    log.warning(f"[UNBLOCK] failed sw={sw} port={port}: {e}")
            SHUTDOWN.wait(0.5)


# ══════════════════════════════════════════════════════════════════════
#  WindowAggregator (v5 logic + latency hooks)
# ══════════════════════════════════════════════════════════════════════
class WindowAggregator:
    def __init__(self, window_sec, model=None,
                 predict_threshold=0.70,
                 port_share_threshold=0.10, port_pkts_threshold=15,
                 blocker=None, observation_sec=3600.0,
                 base_penalty_sec=5.0, max_penalty_sec=900.0,
                 latency_recorder=None):
        self.window_sec         = window_sec
        self.lock               = threading.Lock()
        self._processing_lock   = threading.Lock()
        self._model             = model
        self._predict_threshold = predict_threshold
        self._port_share_thr    = port_share_threshold
        self._port_pkts_thr     = port_pkts_threshold
        self._blocker           = blocker
        self._observation_sec   = observation_sec
        self._base_penalty_sec  = base_penalty_sec
        self._max_penalty_sec   = max_penalty_sec
        self._latency           = latency_recorder

        self._prev_src_ips  = set()
        self._prev_arp_rate = 0.0
        self._window_seq    = 0

        self._defaulters     = {}
        self._defaulter_lock = threading.Lock()

        self._reset()

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
        self.port_reqcounts = collections.Counter()
        self.port_digests   = collections.Counter()
        self.n_packetin   = 0
        self.window_drops = 0
        self._drops_by_iface = collections.Counter()
        self.win_start    = time.time()

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
                if h.opcode == 1:
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
        if snap is not None:
            if self._processing_lock.acquire(blocking=False):
                try:
                    self._process_snapshot(snap)
                except Exception as e:
                    log.error(f"[WIN] failed: {e}")
                finally:
                    self._processing_lock.release()
            else:
                log.warning(f"[WIN] seq={snap['seq']} skipped — still processing")
        self._cleanup_defaulters()

    def _snapshot_and_reset(self):
        self._window_seq += 1
        elapsed  = max(time.time() - self.win_start, 0.001)
        arp_rate = round(self.agg_total / elapsed, 4)
        usip     = set(self.sip_list)

        snap = {
            'seq':            self._window_seq,
            'win_start':      self.win_start,
            'arp_rate':       arp_rate,
            'prev_arp_rate':  self._prev_arp_rate,
            'prev_src_ips':   self._prev_src_ips,
            'usip':           usip,
            'agg_total':      self.agg_total,
            'agg_req':        self.agg_req,
            'agg_rep':        self.agg_rep,
            'agg_grat':       self.agg_grat,
            'agg_bcast':      self.agg_bcast,
            'agg_selfmm':     self.agg_selfmm,
            'sip_list':       list(self.sip_list),
            'smac_list':      list(self.smac_list),
            'tip_list':       list(self.tip_list),
            'swid_list':      list(self.swid_list),
            'port_pktcounts': dict(self.port_pktcounts),
            'port_reqcounts': dict(self.port_reqcounts),
            'n_packetin':     self.n_packetin,
            'window_drops':   self.window_drops,
            'drops_by_iface': dict(self._drops_by_iface),
        }

        self._prev_src_ips  = usip
        self._prev_arp_rate = arp_rate
        self._reset()
        return snap

    def _process_snapshot(self, snap):
        raw_total  = snap['agg_total']
        raw_req    = snap['agg_req']
        raw_rep    = snap['agg_rep']
        raw_grat   = snap['agg_grat']
        raw_bcast  = snap['agg_bcast']
        raw_selfmm = snap['agg_selfmm']
        arp_rate   = snap['arp_rate']

        rr_imbalance = round((raw_req - raw_rep) / (raw_req + raw_rep + 1), 4)
        ip_H  = round(self._entropy(snap['sip_list']), 4)
        mac_H = round(self._entropy(snap['smac_list']), 4)
        tgt_H = round(self._entropy(snap['tip_list']), 4)

        usip = snap['usip']
        uniq_src = len(usip)
        uniq_tgt = len(set(snap['tip_list']))

        bcast_frac = round(raw_bcast / (raw_total + 1), 4)
        grat_frac  = round(raw_grat  / (raw_total + 1), 4)
        self_mm    = raw_selfmm
        drate      = round(arp_rate - snap['prev_arp_rate'], 4)

        new_ip_ratio = (round(len(usip - snap['prev_src_ips']) / len(usip), 4)
                        if usip else 0.0)
        cross_spread = len(set(snap['swid_list']))

        port_pkts  = snap['port_pktcounts']
        port_reqs  = snap.get('port_reqcounts', {})
        total_pkts = sum(port_pkts.values())
        total_reqs = sum(port_reqs.values())

        if port_pkts and total_pkts > 0:
            if port_reqs and total_reqs > 0:
                (top_sw, top_port), top_reqs = max(
                    port_reqs.items(), key=lambda kv: kv[1])
                share = round(top_reqs / total_reqs, 4)
                top_pkts = port_pkts.get((top_sw, top_port), 0)
            else:
                (top_sw, top_port), top_pkts = max(
                    port_pkts.items(), key=lambda kv: kv[1])
                share = round(top_pkts / total_pkts, 4)
            uniq_ports = len(port_pkts)
        else:
            top_sw = top_port = top_pkts = 0
            share = 0.0
            uniq_ports = 0

        if snap['sip_list']:
            ctr = collections.Counter(snap['sip_list'])
            top_ip, top_cnt = ctr.most_common(1)[0]
            top_ip_share = round(top_cnt / len(snap['sip_list']), 4)
        else:
            top_ip, top_cnt, top_ip_share = "-", 0, 0.0

        ts = datetime.fromtimestamp(snap['win_start']).isoformat(timespec="seconds")
        drops_str = " ".join(f"{k}={v}" for k, v in sorted(snap['drops_by_iface'].items()) if v > 0)

        log.info(
            f"[WIN] {ts} | seq={snap['seq']} digests={snap['n_packetin']:4d} "
            f"drops={snap['window_drops']:3d} [{drops_str or '-'}] | "
            f"rate={arp_rate:8.2f}pp  H_src={ip_H:5.3f} H_mac={mac_H:5.3f} "
            f"uniq_src={uniq_src:3d} bcast%={bcast_frac:.2f} "
            f"top_port=s{top_sw}/p{top_port} share={share*100:.1f}% "
            f"pkts={top_pkts} uniq_ports={uniq_ports}"
        )

        if self._model is None:
            return

        feat_vec = [
            arp_rate, rr_imbalance,
            ip_H, uniq_src,
            mac_H, tgt_H, uniq_tgt,
            bcast_frac, grat_frac,
            self_mm, drate,
            new_ip_ratio, cross_spread,
            share, uniq_ports,
        ]
        try:
            proba = float(self._model.predict_proba([feat_vec])[0][1])
        except Exception as e:
            log.warning(f"[PREDICT] model inference failed: {e}")
            return

        t_pred_done = time.time()

        is_attack  = proba >= self._predict_threshold
        can_block  = (share >= self._port_share_thr
                      and top_pkts >= self._port_pkts_thr)
        will_block = is_attack and can_block

        log.info(
            f"[PREDICT] prob_attack={proba:.3f} is_attack={is_attack} "
            f"share={share:.2f} pkts={top_pkts} will_block={will_block}"
        )

        result = None
        if will_block and self._blocker is not None:
            result = self._handle_attack(top_sw, top_port, share, top_pkts, proba)

        if is_attack and self._latency is not None:
            try:
                t_window_end = snap['win_start'] + self.window_sec
                detection_ms = (t_pred_done - t_window_end) * 1000.0

                row = {
                    'timestamp':          datetime.now().isoformat(timespec='milliseconds'),
                    'window_start':       datetime.fromtimestamp(snap['win_start']).isoformat(timespec='milliseconds'),
                    'window_end':         datetime.fromtimestamp(t_window_end).isoformat(timespec='milliseconds'),
                    'seq':                snap['seq'],
                    'arp_rate':           arp_rate,
                    'prob_attack':        round(proba, 4),
                    'is_attack':          1,
                    'can_block':          int(can_block),
                    'will_block':         int(will_block),
                    'top_sw':             top_sw,
                    'top_port':           top_port,
                    'share':              share,
                    'top_pkts':           top_pkts,
                    'model_latency_ms':   round(detection_ms, 3),
                    'rule_install_ms':    '',
                    'total_latency_ms':   '',
                    'install_status':     'no_port' if not can_block else 'skipped',
                    'block_duration_sec': 0,
                    'block_count':        0,
                }

                if result is not None:
                    row['install_status']     = result['status']
                    row['block_duration_sec'] = round(result['block_duration'], 3)
                    row['block_count']        = result['block_count']
                    if (result.get('install_done') is not None
                        and result.get('install_start') is not None):
                        rule_ms  = (result['install_done'] - result['install_start']) * 1000.0
                        total_ms = (result['install_done'] - t_window_end) * 1000.0
                        row['rule_install_ms']  = round(rule_ms, 3)
                        row['total_latency_ms'] = round(total_ms, 3)

                self._latency.write(row)

                if row['total_latency_ms'] != '':
                    log.info(
                        f"[LATENCY] seq={snap['seq']} status={row['install_status']} "
                        f"model={row['model_latency_ms']}ms "
                        f"rule={row['rule_install_ms']}ms "
                        f"total={row['total_latency_ms']}ms")
                else:
                    log.info(
                        f"[LATENCY] seq={snap['seq']} status={row['install_status']} "
                        f"model={row['model_latency_ms']}ms (no rule installed)")
            except Exception as e:
                log.warning(f"[LATENCY] failed to record: {e}")

    def _handle_attack(self, sw, port, share, pkts, proba):
        now = time.time()
        key = (sw, port)

        result = {
            'install_start':   None,
            'install_done':    None,
            'install_success': False,
            'status':          'failed',
            'block_duration':  0.0,
            'block_count':     0,
        }

        with self._defaulter_lock:
            d = self._defaulters.get(key)
            if d is None or (not d.is_blocked(now) and not d.is_observed(now)):
                d = Defaulter(sw, port, now)
                self._defaulters[key] = d

            if d.is_blocked(now):
                log.info(f"[ATTACK] sw={sw} port={port} already blocked "
                         f"(until +{d.block_until - now:.0f}s, hit #{d.block_count})")
                result['status'] = 'blocked'
                result['block_count'] = d.block_count
                return result

            penalty = d.register_attack(now, self._base_penalty_sec,
                                        self._max_penalty_sec,
                                        self._observation_sec)
            result['block_duration'] = penalty
            result['block_count']    = d.block_count
            log.info(f"[ATTACK] sw={sw} port={port} proba={proba:.3f} "
                     f"share={share:.2f} pkts={pkts} → block #{d.block_count} "
                     f"for {penalty:.0f}s")

        if self._blocker is not None:
            result['install_start'] = time.time()
            handle = self._blocker.install(sw, port, penalty,
                                            reason=f"attack#{d.block_count}")
            result['install_done']  = time.time()
            result['install_success'] = handle is not None
            result['status'] = 'ok' if handle is not None else 'failed'

        return result

    def _cleanup_defaulters(self):
        now = time.time()
        expired = []
        with self._defaulter_lock:
            for key, d in list(self._defaulters.items()):
                if not d.is_blocked(now) and not d.is_observed(now):
                    expired.append(key)
                    self._defaulters.pop(key, None)
        for (sw, port) in expired:
            log.info(f"[STATE] forgot sw={sw} port={port} — "
                     f"1h observation expired")

    @staticmethod
    def _entropy(items):
        if not items:
            return 0.0
        c = collections.Counter(items)
        t = len(items)
        return -sum((v / t) * math.log2(v / t) for v in c.values())

    def close(self):
        if self._latency is not None:
            self._latency.close()


# ══════════════════════════════════════════════════════════════════════
#  Sniffer (identical to v5)
# ══════════════════════════════════════════════════════════════════════
_agg: WindowAggregator = None


def _open_raw_socket(iface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_ALL))
    except OSError as e:
        log.debug(f"[SNIFF] {iface} socket failed: {e}")
        return None

    actual_kb = 0
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, SO_RCVBUF_BYTES)
        actual_kb = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) // 1024
        log.info(f"[SNIFF] {iface} buffer=FORCE {actual_kb//1024} MB")
    except (OSError, PermissionError) as e:
        log.warning(f"[SNIFF] {iface} FORCE failed ({e}) — trying RCVBUF")
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_BYTES)
            actual_kb = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) // 1024
            log.info(f"[SNIFF] {iface} buffer=RCVBUF {actual_kb//1024} MB")
        except OSError as e2:
            log.warning(f"[SNIFF] {iface} RCVBUF failed: {e2}")

    if actual_kb < 4096:
        log.warning(f"[SNIFF] {iface} buffer is only {actual_kb} KB — drops likely")

    try:
        s.bind((iface, ETH_P_ALL))
        s.setblocking(False)
        return s
    except OSError as e:
        log.debug(f"[SNIFF] {iface} bind failed: {e}")
        try: s.close()
        except Exception: pass
        return None


def _sniff_thread(iface):
    announced_wait = False
    while not SHUTDOWN.is_set():
        sock = _open_raw_socket(iface)
        if sock is None:
            if not announced_wait:
                log.info(f"[SNIFF] Waiting for {iface} ...")
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
            log.warning(f"[SNIFF] {iface} lost: {e}. Reconnecting...")
        except Exception as e:
            log.warning(f"[SNIFF] {iface} error: {e}. Reconnecting...")
        finally:
            try: sock.close()
            except Exception: pass
        if SHUTDOWN.wait(IFACE_RETRY_SEC):
            return


# ══════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════
def _load_model(path):
    if not path:
        return None
    if not os.path.exists(path):
        log.error(f"[MODEL] {path} not found")
        return None
    try:
        import joblib
        m = joblib.load(path)
        log.info(f"[MODEL] Loaded {path} ({type(m).__name__})")
        return m
    except Exception as e:
        log.error(f"[MODEL] Failed to load {path}: {e}")
        return None


def main():
    global _agg

    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="ARP Flood Detection Controller v6 — runtime detection + "
                    "escalating port blocking + action-latency CSV.",
    )
    ap.add_argument("--interfaces", "-i", nargs="+", required=True)
    ap.add_argument("--window",  "-w", type=int, default=WINDOW_SEC)
    ap.add_argument("--model",   "-m", default=None)
    ap.add_argument("--predict-threshold",    type=float, default=0.70)
    ap.add_argument("--port-share-threshold", type=float, default=0.10)
    ap.add_argument("--port-pkts-threshold",  type=int,   default=15)
    ap.add_argument("--observation-sec",      type=float, default=3600.0)
    ap.add_argument("--base-penalty-sec",     type=float, default=5.0)
    ap.add_argument("--max-penalty-sec",      type=float, default=900.0)

    ap.add_argument("--latency-csv", default=_default_latency_csv(),
                    help="Append-mode CSV for detection+mitigation latency "
                         "(default: <project>/action_latency.csv). "
                         "Pass '' to disable.")

    ap.add_argument("--dataset", "-d", default=None)
    ap.add_argument("--label",   "-l", default=None)
    ap.add_argument("--block-hold", type=float, default=None)

    args = ap.parse_args()

    if os.geteuid() != 0:
        log.error("needs root (AF_PACKET)")
        sys.exit(1)

    if args.dataset:
        log.warning(f"[DEPRECATED] --dataset={args.dataset} ignored")
    if args.label:
        log.warning(f"[DEPRECATED] --label={args.label} ignored")
    if args.block_hold:
        log.warning(f"[DEPRECATED] --block-hold={args.block_hold} ignored")

    log.info("=" * 72)
    log.info("  ARP Flood Detection Controller v6 (action-latency)")
    log.info(f"  Interfaces     : {args.interfaces}")
    log.info(f"  Window         : {args.window}s")
    log.info(f"  Model          : {args.model or '(none — monitor only)'}")
    log.info(f"  Predict thr    : {args.predict_threshold}")
    log.info(f"  Port share thr : {args.port_share_threshold}")
    log.info(f"  Port pkts thr  : {args.port_pkts_threshold}")
    log.info(f"  Observation    : {args.observation_sec:.0f}s")
    log.info(f"  Penalties      : {args.base_penalty_sec:.0f}s → "
             f"{args.max_penalty_sec:.0f}s (doubling per defaulter)")
    log.info(f"  Latency CSV    : {args.latency_csv or '(disabled)'}"
             f"{' [append]' if args.latency_csv else ''}")
    log.info("=" * 72)

    model   = _load_model(args.model)
    blocker = PortBlocker() if model else None
    if model is None:
        log.warning("[CTRL] No model loaded — passive monitoring only")

    latency_rec = (LatencyRecorder(args.latency_csv)
                   if args.latency_csv else None)

    _agg = WindowAggregator(
        args.window, model=model,
        predict_threshold=args.predict_threshold,
        port_share_threshold=args.port_share_threshold,
        port_pkts_threshold=args.port_pkts_threshold,
        blocker=blocker,
        observation_sec=args.observation_sec,
        base_penalty_sec=args.base_penalty_sec,
        max_penalty_sec=args.max_penalty_sec,
        latency_recorder=latency_rec,
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
                         name="block-expire", daemon=True).start()

    def _toggle(sig, frame):
        log.info("[SIGUSR1] ignored (no label to toggle)")
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

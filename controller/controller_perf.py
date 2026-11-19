#!/usr/bin/env python3
"""
controller_perf.py — ARP controller LOAD MEASUREMENT build
====================================================================
Does the full controller workload (parse digests, aggregate window,
compute all 15 features, optional model inference) but:
  * features are computed and DISCARDED (never stored)
  * NO blocking
  * ONE csv is written: ./dataset/<mode>_perf_<timestamp>.csv
    with one row per window of load/performance metrics.

Modes (you load the matching P4 on the switches yourself):
  current  : old P4, sampled (1 in 3, edge-origin only). Digest counters
             are per-window deltas (reset on every digest).
  baseline : new P4, digest on EVERY ARP on EVERY switch. Digest counters
             are cumulative, so the controller uses per-switch deltas.

USAGE:
    sudo python3 controller/controller_perf.py --mode current \
        --interfaces s1-cpu1 s2-cpu1 s3-cpu1 s4-cpu1 s11-cpu1 \
        --model models/arp_rf.pkl --duration 240

    sudo python3 controller/controller_perf.py --mode baseline \
        --interfaces s1-cpu1 s2-cpu1 s3-cpu1 s4-cpu1 s11-cpu1 \
        --model models/arp_rf.pkl --duration 240

    (omit --mode and you will be asked interactively)
"""

import os, sys, time, struct, math, socket, select, csv
import threading, collections, logging, argparse, signal
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/controller_perf.log"),
    ]
)
log = logging.getLogger("perf")

# ── Config ────────────────────────────────────────────────────────────
WINDOW_SEC      = 1
CPU_REASON      = 0xAA
IFACE_RETRY_SEC = 2
ETH_P_ALL       = 0x0003
RECV_BUF_SIZE   = 65535
SO_RCVBUF_BYTES = 64 * 1024 * 1024
SO_RCVBUFFORCE  = 33
DRAIN_CAP       = 1024            # max packets drained per select wake-up
SHUTDOWN        = threading.Event()

SOL_PACKET        = 263
PACKET_STATISTICS = 6
TPACKET_STATS_FMT = "II"
TPACKET_STATS_LEN = struct.calcsize(TPACKET_STATS_FMT)

EDGE_SWITCHES = {1, 2, 3, 4}
CENTRAL_SWITCH = 11
HOST_PORT_MAX = 15

# Order the model expects (features are built then discarded)
FEATURE_COLUMNS = [
    "arp_rate", "request_reply_imbalance",
    "src_ip_entropy", "unique_src_ip_count",
    "src_mac_entropy", "target_ip_entropy", "unique_target_ip_count",
    "broadcast_fraction", "gratuitous_fraction",
    "self_mac_mismatch_count", "delta_arp_rate",
    "new_ip_ratio", "cross_switch_spread",
    "top_port_share", "unique_host_ports",
]

CSV_COLUMNS = [
    "window_seq", "timestamp", "mode", "t_since_start_s", "window_elapsed_s",
    # digest throughput
    "digests_processed", "digests_per_sec", "edge_origin_digests",
    "digests_sw1", "digests_sw2", "digests_sw3", "digests_sw4",
    "digests_sw11", "digests_other", "arp_pkts_represented",
    # socket / kernel level
    "kernel_pkts_offered", "kernel_drops", "drop_pct",
    "raw_pkts_recv", "non_digest_pkts", "bytes_recv",
    # controller processing cost
    "avg_ingest_us", "max_ingest_us",
    "feature_calc_ms", "predict_ms", "prob_attack",
    # controller process resources
    "proc_cpu_pct", "proc_cpu_user_pct", "proc_cpu_sys_pct", "proc_cpu_pct_norm",
    "proc_rss_mb", "proc_peak_rss_mb", "proc_vms_mb", "num_threads",
    # whole machine
    "sys_cpu_pct", "load1", "sys_mem_used_mb", "sys_mem_used_pct",
    "sample_dt_s",
]

CPU_FMT  = "!BB H 4s 6s 4s H IIIII BI"
CPU_SIZE = struct.calcsize(CPU_FMT)
assert CPU_SIZE == 45


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


def _read_socket_stats(sock):
    """Returns (tp_packets, tp_drops) since last read (kernel resets on read).
    tp_packets already includes the dropped ones = offered load."""
    try:
        data = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, TPACKET_STATS_LEN)
        pk, dr = struct.unpack(TPACKET_STATS_FMT, data)
        return pk, dr
    except OSError:
        return 0, 0


# ══════════════════════════════════════════════════════════════════════
#  RESOURCE SAMPLER  (/proc based, no external dependencies)
# ══════════════════════════════════════════════════════════════════════

class ResourceSampler:
    def __init__(self):
        self.clk  = os.sysconf("SC_CLK_TCK")
        self.ncpu = os.cpu_count() or 1
        self.mem_total_kb = self._meminfo().get("MemTotal", 0)
        self._prev_wall = time.monotonic()
        self._prev_proc = self._proc_ticks()
        self._prev_sys  = self._sys_ticks()

    @staticmethod
    def _proc_ticks():
        try:
            with open("/proc/self/stat") as f:
                data = f.read()
            rest = data[data.rindex(")") + 2:].split()
            # field n -> rest[n-3]: utime=14, stime=15, num_threads=20
            return int(rest[11]), int(rest[12]), int(rest[17])
        except Exception:
            return 0, 0, 1

    @staticmethod
    def _sys_ticks():
        try:
            with open("/proc/stat") as f:
                vals = [int(x) for x in f.readline().split()[1:9]]
            total = sum(vals)
            idle  = vals[3] + (vals[4] if len(vals) > 4 else 0)
            return total, idle
        except Exception:
            return 0, 0

    @staticmethod
    def _status_kb():
        out = {}
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith(("VmRSS", "VmHWM", "VmSize")):
                        k, v = line.split(":", 1)
                        out[k] = int(v.split()[0])
        except Exception:
            pass
        return out

    @staticmethod
    def _meminfo():
        out = {}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    k, v = line.split(":", 1)
                    out[k] = int(v.split()[0])
        except Exception:
            pass
        return out

    def sample(self):
        now = time.monotonic()
        dt  = max(now - self._prev_wall, 1e-6)

        ut, st, nth = self._proc_ticks()
        d_user = (ut - self._prev_proc[0]) / self.clk
        d_sys  = (st - self._prev_proc[1]) / self.clk
        user_pct = 100.0 * d_user / dt
        sys_pct  = 100.0 * d_sys  / dt
        proc_pct = user_pct + sys_pct          # % of ONE core

        s_total, s_idle = self._sys_ticks()
        d_tot  = s_total - self._prev_sys[0]
        d_idle = s_idle  - self._prev_sys[1]
        sys_cpu = 100.0 * (1.0 - d_idle / d_tot) if d_tot > 0 else 0.0

        stt = self._status_kb()
        mem = self._meminfo()
        used_kb = mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)
        used_pct = 100.0 * used_kb / self.mem_total_kb if self.mem_total_kb else 0.0
        try:
            load1 = os.getloadavg()[0]
        except OSError:
            load1 = 0.0

        self._prev_wall = now
        self._prev_proc = (ut, st, nth)
        self._prev_sys  = (s_total, s_idle)

        return {
            "proc_cpu_pct":      proc_pct,
            "proc_cpu_user_pct": user_pct,
            "proc_cpu_sys_pct":  sys_pct,
            "proc_cpu_pct_norm": proc_pct / self.ncpu,
            "proc_rss_mb":       stt.get("VmRSS", 0) / 1024.0,
            "proc_peak_rss_mb":  stt.get("VmHWM", 0) / 1024.0,
            "proc_vms_mb":       stt.get("VmSize", 0) / 1024.0,
            "num_threads":       nth,
            "sys_cpu_pct":       sys_cpu,
            "load1":             load1,
            "sys_mem_used_mb":   used_kb / 1024.0,
            "sys_mem_used_pct":  used_pct,
            "sample_dt_s":       dt,
        }


# ══════════════════════════════════════════════════════════════════════
#  PERF CSV WRITER
# ══════════════════════════════════════════════════════════════════════

class PerfWriter:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "w", newline="")
        self.w = csv.DictWriter(self.f, fieldnames=CSV_COLUMNS)
        self.w.writeheader()
        self.f.flush()
        self.rows = []

    def write(self, row):
        self.w.writerow(row)
        self.f.flush()
        self.rows.append(row)

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  WINDOW AGGREGATOR
# ══════════════════════════════════════════════════════════════════════

class WindowAggregator:
    def __init__(self, window_sec, mode, writer, model=None):
        self.window_sec       = window_sec
        self.mode             = mode
        self._writer          = writer
        self._model           = model
        self.lock             = threading.Lock()
        self._processing_lock = threading.Lock()
        self._sampler         = ResourceSampler()
        self.t_start          = time.time()

        self._prev_src_ips  = set()
        self._prev_arp_rate = 0.0
        self._window_seq    = 0
        self._prev_cum      = {}      # baseline mode: switch_id -> cumulative regs

        self._reset()

    # ── window state ────────────────────────────────────────────────
    def _reset(self):
        self.agg_total = self.agg_req = self.agg_rep = 0
        self.agg_grat = self.agg_bcast = self.agg_selfmm = 0
        self.sip_list, self.smac_list = [], []
        self.tip_list, self.swid_list = [], []
        self.port_pktcounts = collections.Counter()
        self.port_reqcounts = collections.Counter()
        self.n_packetin = 0
        self.edge_origin = 0
        self.sw_digests = collections.Counter()
        # perf counters
        self.raw_pkts = self.raw_bytes = self.non_digest = 0
        self.k_pkts = self.k_drops = 0
        self.drops_by_iface = collections.Counter()
        self.ingest_ns_sum = 0
        self.ingest_ns_max = 0
        self.win_start = time.time()

    # ── per-digest deltas ───────────────────────────────────────────
    def _baseline_deltas(self, h):
        """Baseline P4 sends CUMULATIVE counters per switch → use deltas."""
        cur  = (h.reg_total, h.reg_req, h.reg_rep,
                h.reg_grat, h.reg_bcast, h.reg_self_mismatch)
        prev = self._prev_cum.get(h.switch_id)
        self._prev_cum[h.switch_id] = cur
        if prev is None or cur[0] < prev[0]:        # first digest / restart
            return (1, int(h.opcode == 1), int(h.opcode == 2),
                    int(h.sender_ip == h.target_ip), 0, 0)
        return tuple(max(c - p, 0) for c, p in zip(cur, prev))

    # ── ingest (called from sniff threads) ──────────────────────────
    def ingest(self, h: CpuHeader, parse_ns=0):
        t0 = time.perf_counter_ns()
        with self.lock:
            if self.mode == "current":
                d_tot, d_req, d_rep, d_grat, d_bc, d_mm = (
                    h.reg_total, h.reg_req, h.reg_rep,
                    h.reg_grat, h.reg_bcast, h.reg_self_mismatch)
                port_w = h.reg_total
            else:
                d_tot, d_req, d_rep, d_grat, d_bc, d_mm = self._baseline_deltas(h)
                port_w = 1

            self.agg_total  += d_tot
            self.agg_req    += d_req
            self.agg_rep    += d_rep
            self.agg_grat   += d_grat
            self.agg_bcast  += d_bc
            self.agg_selfmm += d_mm
            self.sip_list.append(h.sender_ip)
            self.smac_list.append(h.sender_mac)
            self.tip_list.append(h.target_ip)
            self.swid_list.append(h.switch_id)
            self.n_packetin += 1
            self.sw_digests[h.switch_id] += 1

            if h.switch_id in EDGE_SWITCHES and h.ingress_port < HOST_PORT_MAX:
                self.edge_origin += 1
                key = (h.switch_id, h.ingress_port)
                self.port_pktcounts[key] += port_w
                if h.opcode == 1:
                    self.port_reqcounts[key] += port_w

            cost = parse_ns + (time.perf_counter_ns() - t0)
            self.ingest_ns_sum += cost
            if cost > self.ingest_ns_max:
                self.ingest_ns_max = cost

    def note_io(self, iface, raw_n, raw_bytes, non_digest, k_pkts, k_drops):
        if not (raw_n or raw_bytes or non_digest or k_pkts or k_drops):
            return
        with self.lock:
            self.raw_pkts   += raw_n
            self.raw_bytes  += raw_bytes
            self.non_digest += non_digest
            self.k_pkts     += k_pkts
            self.k_drops    += k_drops
            if k_drops:
                self.drops_by_iface[iface] += k_drops

    # ── tick / window close ─────────────────────────────────────────
    def tick(self):
        snap = None
        with self.lock:
            if time.time() - self.win_start >= self.window_sec:
                snap = self._snapshot_and_reset()
        if snap is None:
            return
        if not self._processing_lock.acquire(blocking=False):
            log.warning(f"[WIN] seq={snap['seq']} skipped — still processing")
            return
        try:
            self._process_and_record(snap)
        except Exception as e:
            log.error(f"[WIN] failed: {e}")
        finally:
            self._processing_lock.release()

    def _snapshot_and_reset(self):
        self._window_seq += 1
        now      = time.time()
        elapsed  = max(now - self.win_start, 0.001)
        arp_rate = round(self.agg_total / elapsed, 4)
        usip     = set(self.sip_list)

        snap = {
            'seq': self._window_seq, 'win_start': self.win_start, 'win_end': now,
            'elapsed': elapsed,
            'arp_rate': arp_rate, 'prev_arp_rate': self._prev_arp_rate,
            'prev_src_ips': self._prev_src_ips, 'usip': usip,
            'agg_total': self.agg_total, 'agg_req': self.agg_req,
            'agg_rep': self.agg_rep, 'agg_grat': self.agg_grat,
            'agg_bcast': self.agg_bcast, 'agg_selfmm': self.agg_selfmm,
            'sip_list': list(self.sip_list), 'smac_list': list(self.smac_list),
            'tip_list': list(self.tip_list), 'swid_list': list(self.swid_list),
            'port_pktcounts': dict(self.port_pktcounts),
            'port_reqcounts': dict(self.port_reqcounts),
            'n_packetin': self.n_packetin, 'edge_origin': self.edge_origin,
            'sw_digests': dict(self.sw_digests),
            'raw_pkts': self.raw_pkts, 'raw_bytes': self.raw_bytes,
            'non_digest': self.non_digest,
            'k_pkts': self.k_pkts, 'k_drops': self.k_drops,
            'drops_by_iface': dict(self.drops_by_iface),
            'ingest_ns_sum': self.ingest_ns_sum, 'ingest_ns_max': self.ingest_ns_max,
        }
        self._prev_src_ips  = usip
        self._prev_arp_rate = arp_rate
        self._reset()
        return snap

    # ── full feature computation (result is thrown away) ────────────
    def _compute_features(self, snap):
        raw_total, raw_req, raw_rep = snap['agg_total'], snap['agg_req'], snap['agg_rep']
        arp_rate = snap['arp_rate']

        rr_imb = round((raw_req - raw_rep) / (raw_req + raw_rep + 1), 4)
        ip_H   = round(self._entropy(snap['sip_list']), 4)
        mac_H  = round(self._entropy(snap['smac_list']), 4)
        tgt_H  = round(self._entropy(snap['tip_list']), 4)

        usip     = snap['usip']
        uniq_src = len(usip)
        uniq_tgt = len(set(snap['tip_list']))

        bcast_frac = round(snap['agg_bcast'] / (raw_total + 1), 4)
        grat_frac  = round(snap['agg_grat']  / (raw_total + 1), 4)
        drate      = round(arp_rate - snap['prev_arp_rate'], 4)
        new_ip_ratio = (round(len(usip - snap['prev_src_ips']) / len(usip), 4)
                        if usip else 0.0)
        cross_spread = len(set(snap['swid_list']))

        port_pkts, port_reqs = snap['port_pktcounts'], snap['port_reqcounts']
        total_pkts, total_reqs = sum(port_pkts.values()), sum(port_reqs.values())
        if port_pkts and total_pkts > 0:
            if port_reqs and total_reqs > 0:
                (_sw, _p), top_reqs = max(port_reqs.items(), key=lambda kv: kv[1])
                share = round(top_reqs / total_reqs, 4)
            else:
                (_sw, _p), top_pkts = max(port_pkts.items(), key=lambda kv: kv[1])
                share = round(top_pkts / total_pkts, 4)
            uniq_ports = len(port_pkts)
        else:
            share, uniq_ports = 0.0, 0

        if snap['sip_list']:                       # top-IP work kept for cost parity
            ctr = collections.Counter(snap['sip_list'])
            _top_ip, _top_cnt = ctr.most_common(1)[0]

        return [arp_rate, rr_imb, ip_H, uniq_src, mac_H, tgt_H, uniq_tgt,
                bcast_frac, grat_frac, raw_selfmm_safe(snap), drate,
                new_ip_ratio, cross_spread, share, uniq_ports]

    def _process_and_record(self, snap):
        t0 = time.perf_counter()
        feat_vec = self._compute_features(snap)
        feature_ms = (time.perf_counter() - t0) * 1000.0

        prob, predict_ms = "", 0.0
        if self._model is not None:
            t1 = time.perf_counter()
            try:
                prob = round(float(self._model.predict_proba([feat_vec])[0][1]), 4)
            except Exception as e:
                log.warning(f"[PREDICT] inference failed: {e}")
            predict_ms = (time.perf_counter() - t1) * 1000.0

        del feat_vec                                  # → trash, never stored

        res = self._sampler.sample()

        n       = snap['n_packetin']
        el      = snap['elapsed']
        k_pkts  = snap['k_pkts']
        k_drops = snap['k_drops']
        swd     = snap['sw_digests']
        known   = {1, 2, 3, 4, 11}
        other   = sum(v for k, v in swd.items() if k not in known)

        row = {
            "window_seq": snap['seq'],
            "timestamp": datetime.fromtimestamp(snap['win_start']).isoformat(timespec="milliseconds"),
            "mode": self.mode,
            "t_since_start_s": round(snap['win_end'] - self.t_start, 3),
            "window_elapsed_s": round(el, 4),
            "digests_processed": n,
            "digests_per_sec": round(n / el, 2),
            "edge_origin_digests": snap['edge_origin'],
            "digests_sw1": swd.get(1, 0), "digests_sw2": swd.get(2, 0),
            "digests_sw3": swd.get(3, 0), "digests_sw4": swd.get(4, 0),
            "digests_sw11": swd.get(11, 0), "digests_other": other,
            "arp_pkts_represented": snap['agg_total'],
            "kernel_pkts_offered": k_pkts,
            "kernel_drops": k_drops,
            "drop_pct": round(100.0 * k_drops / k_pkts, 3) if k_pkts else 0.0,
            "raw_pkts_recv": snap['raw_pkts'],
            "non_digest_pkts": snap['non_digest'],
            "bytes_recv": snap['raw_bytes'],
            "avg_ingest_us": round(snap['ingest_ns_sum'] / n / 1000.0, 3) if n else 0.0,
            "max_ingest_us": round(snap['ingest_ns_max'] / 1000.0, 3),
            "feature_calc_ms": round(feature_ms, 3),
            "predict_ms": round(predict_ms, 3),
            "prob_attack": prob,
        }
        for k, v in res.items():
            row[k] = round(v, 3) if isinstance(v, float) else v

        self._writer.write(row)
        log.info(
            f"[PERF] seq={row['window_seq']:4d} dig={n:5d} ({row['digests_per_sec']:8.1f}/s) "
            f"offered={k_pkts:5d} drops={k_drops:4d} ({row['drop_pct']:5.1f}%) "
            f"cpu={row['proc_cpu_pct']:5.1f}% sys_cpu={row['sys_cpu_pct']:5.1f}% "
            f"rss={row['proc_rss_mb']:6.1f}MB feat={feature_ms:6.1f}ms"
        )

    @staticmethod
    def _entropy(items):
        if not items:
            return 0.0
        c = collections.Counter(items)
        t = len(items)
        return -sum((v / t) * math.log2(v / t) for v in c.values())


def raw_selfmm_safe(snap):
    return snap['agg_selfmm']


# ══════════════════════════════════════════════════════════════════════
#  SNIFFER
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
        log.warning(f"[SNIFF] {iface} buffer only {actual_kb} KB — drops likely")

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
        _read_socket_stats(sock)                      # clear counters
        try:
            while not SHUTDOWN.is_set():
                r, _, _ = select.select([sock], [], [], 0.5)
                if not r:
                    kp, kd = _read_socket_stats(sock)
                    _agg.note_io(iface, 0, 0, 0, kp, kd)
                    continue
                n = nbytes = nondig = 0
                while n < DRAIN_CAP:
                    try:
                        raw, _addr = sock.recvfrom(RECV_BUF_SIZE)
                    except BlockingIOError:
                        break
                    if not raw:
                        continue
                    n += 1
                    nbytes += len(raw)
                    t0 = time.perf_counter_ns()
                    h = CpuHeader.parse(raw)
                    parse_ns = time.perf_counter_ns() - t0
                    if h is None:
                        nondig += 1
                        continue
                    _agg.ingest(h, parse_ns)
                kp, kd = _read_socket_stats(sock)
                _agg.note_io(iface, n, nbytes, nondig, kp, kd)
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
#  MAIN
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


def _choose_mode(arg):
    if arg:
        return arg
    if not sys.stdin.isatty():
        log.error("No --mode given and stdin is not interactive")
        sys.exit(1)
    print("\nSelect controller mode:")
    print("  1) current  — OLD P4: sampled, 1 digest per 3 ARP, edge-origin only")
    print("  2) baseline — NEW P4: digest on EVERY ARP, every switch, every port")
    while True:
        c = input("Enter 1 or 2 (or 'current' / 'baseline'): ").strip().lower()
        if c in ("1", "current"):
            return "current"
        if c in ("2", "baseline"):
            return "baseline"
        print("Invalid choice.")


def _print_summary(rows, path, mode):
    if not rows:
        log.warning("[SUMMARY] no windows recorded")
        return
    keys = ["digests_per_sec", "kernel_pkts_offered", "kernel_drops", "drop_pct",
            "avg_ingest_us", "feature_calc_ms", "predict_ms",
            "proc_cpu_pct", "proc_cpu_pct_norm", "proc_rss_mb",
            "sys_cpu_pct", "load1", "sys_mem_used_pct"]
    log.info("=" * 72)
    log.info(f"  SUMMARY  mode={mode}  windows={len(rows)}")
    log.info(f"  total digests processed : {sum(r['digests_processed'] for r in rows)}")
    log.info(f"  total kernel drops      : {sum(r['kernel_drops'] for r in rows)}")
    for k in keys:
        vals = [r[k] for r in rows if isinstance(r.get(k), (int, float))]
        if vals:
            log.info(f"  {k:22s} mean={sum(vals)/len(vals):10.3f}  max={max(vals):10.3f}")
    log.info(f"  CSV saved: {path}")
    log.info("=" * 72)


def main():
    global _agg

    ap = argparse.ArgumentParser(
        description="ARP controller load-measurement build (no dataset, no blocking).")
    ap.add_argument("--interfaces", "-i", nargs="+", required=True)
    ap.add_argument("--mode", choices=["current", "baseline"], default=None,
                    help="current = old sampled P4, baseline = new all-digest P4 "
                         "(asked interactively if omitted)")
    ap.add_argument("--window", "-w", type=int, default=WINDOW_SEC)
    ap.add_argument("--model", "-m", default=None,
                    help="Optional .pkl; if given, inference cost is measured too "
                         "(use the SAME setting in both runs)")
    ap.add_argument("--duration", type=float, default=0,
                    help="Auto-stop after N seconds (0 = until Ctrl+C)")
    ap.add_argument("--outdir", default="./dataset")
    args = ap.parse_args()

    if os.geteuid() != 0:
        log.error("needs root (AF_PACKET)")
        sys.exit(1)

    mode = _choose_mode(args.mode)

    os.makedirs(args.outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(args.outdir, f"{mode}_perf_{ts}.csv")
    writer = PerfWriter(path)

    log.info("=" * 72)
    log.info("  ARP Controller — PERFORMANCE MEASUREMENT")
    log.info(f"  Mode        : {mode}")
    log.info(f"  Interfaces  : {args.interfaces}")
    log.info(f"  Window      : {args.window}s")
    log.info(f"  Model       : {args.model or '(none — no inference cost)'}")
    log.info(f"  Duration    : {args.duration or 'until Ctrl+C'}")
    log.info(f"  Output CSV  : {path}")
    log.info("  Features    : computed then discarded (not stored)")
    log.info("  Blocking    : DISABLED")
    log.info("=" * 72)

    model = _load_model(args.model)
    _agg = WindowAggregator(args.window, mode, writer, model=model)

    threads = []
    for iface in args.interfaces:
        t = threading.Thread(target=_sniff_thread, args=(iface,),
                             name=f"sniff-{iface}", daemon=True)
        t.start()
        threads.append(t)

    def _ticker():
        while not SHUTDOWN.is_set():
            if SHUTDOWN.wait(0.25):
                return
            _agg.tick()
    threading.Thread(target=_ticker, name="ticker", daemon=True).start()

    signal.signal(signal.SIGTERM, lambda s, f: SHUTDOWN.set())

    log.info(f"[CTRL] PID={os.getpid()}  Running. Ctrl+C to stop.")
    t_begin = time.time()
    try:
        while not SHUTDOWN.is_set():
            time.sleep(0.5)
            if args.duration and time.time() - t_begin >= args.duration:
                log.info("[CTRL] duration reached — stopping")
                break
    except KeyboardInterrupt:
        log.info("[CTRL] Shutting down...")
    finally:
        SHUTDOWN.set()
        for t in threads:
            t.join(timeout=1.0)
        time.sleep(0.3)
        writer.close()
        _print_summary(writer.rows, path, mode)


if __name__ == "__main__":
    main()

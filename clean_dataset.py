# """
# ARP Flood Detection - Dataset Cleaner
# --------------------------------------
# - Removes duplicate rows
# - Removes rows where arp_total == 0
# - Saves cleaned dataset as a new file (original is untouched)

# Dependencies:
#     pip install pandas
# """

# import pandas as pd
# from pathlib import Path


# # ── Config ──────────────────────────────────────────────────────────────────
# INPUT_PATH  = Path("/opt/p4work/arp_flood_detection/dataset/arp_dataset.csv")
# OUTPUT_PATH = INPUT_PATH.parent / "arp_dataset_cleaned.csv"
# # ─────────────────────────────────────────────────────────────────────────────


# def load_dataset(path: Path) -> pd.DataFrame:
#     print(f"[INFO] Loading dataset from: {path}")
#     df = pd.read_csv(path)
#     print(f"[INFO] Original shape: {df.shape[0]} rows × {df.shape[1]} cols")
#     return df


# def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
#     before = len(df)
#     df = df.drop_duplicates()
#     removed = before - len(df)
#     print(f"[CLEAN] Removed {removed} duplicate row(s)  →  {len(df)} rows remaining")
#     return df


# def remove_zero_arp_total(df: pd.DataFrame) -> pd.DataFrame:
#     before = len(df)
#     df = df[df["arp_total"] != 0]
#     removed = before - len(df)
#     print(f"[CLEAN] Removed {removed} row(s) where arp_total == 0  →  {len(df)} rows remaining")
#     return df


# def shuffle_dataset(df: pd.DataFrame) -> pd.DataFrame:
#     df = df.sample(frac=1, random_state=42).reset_index(drop=True)
#     print(f"[CLEAN] Dataset shuffled  →  {len(df)} rows (order fully randomized)")
#     return df


# def save_dataset(df: pd.DataFrame, path: Path) -> None:
#     df.to_csv(path, index=False)
#     print(f"[INFO] Cleaned dataset saved to: {path}")


# def print_distribution(df: pd.DataFrame, title: str) -> None:
#     total = len(df)
#     print(f"\n  {title}  (total: {total} rows)")
#     print("  " + "─" * 50)
#     if total == 0:
#         print("  (no rows in this group)")
#         return
#     counts = df["label"].value_counts()
#     for label, count in counts.items():
#         pct = count / total * 100
#         bar = "█" * int(pct / 2)
#         print(f"  {str(label):>20} : {count:>6} rows  ({pct:5.1f}%)  {bar}")


# def label_summary(df: pd.DataFrame) -> None:
#     sep = "═" * 54

#     # ── Total distribution ───────────────────────────────────
#     print(f"\n{sep}")
#     print("  OVERALL CLASS DISTRIBUTION")
#     print(sep)
#     print_distribution(df, "All rows")

#     # ── arp_total > 300 ──────────────────────────────────────
#     high = df[df["arp_total"] > 300]
#     print(f"\n{sep}")
#     print("  CLASS DISTRIBUTION  —  arp_total > 300")
#     print(sep)
#     print_distribution(high, "arp_total > 300")

#     # ── arp_total <= 300 (already > 0 after cleaning) ────────
#     low = df[df["arp_total"] <= 300]
#     print(f"\n{sep}")
#     print("  CLASS DISTRIBUTION  —  arp_total <= 300  (and > 0)")
#     print(sep)
#     print_distribution(low, "arp_total <= 300")
#     print(f"\n{sep}")


# def main():
#     if not INPUT_PATH.exists():
#         raise FileNotFoundError(f"Dataset not found at: {INPUT_PATH}")

#     df = load_dataset(INPUT_PATH)

#     df = remove_duplicates(df)
#     df = remove_zero_arp_total(df)
#     df = shuffle_dataset(df)

#     label_summary(df)
#     save_dataset(df, OUTPUT_PATH)

#     print(f"\n[DONE] Final shape: {df.shape[0]} rows × {df.shape[1]} cols")
#     print(f"       Original : {INPUT_PATH}")
#     print(f"       Cleaned  : {OUTPUT_PATH}")


# if __name__ == "__main__":
#     main()
#!/usr/bin/env python3
"""
controller.py — ARP Flood Detection Controller (monitoring only, 13 features)
==============================================================================
Passive monitoring only.  No blocking subsystem.

Subsystem:

  (A) Passive monitoring — parses 45-byte P4 CPU-header digests, computes the
      13 ML features per 1-second window, writes them to
      <project>/dataset/arp_dataset_new.csv, and prints one line per window
      to the terminal including ALL raw counters (total, req, rep, grat,
      bcast, selfmm) plus digest count and top source IP.

The P4 program on each switch still contains tbl_block_ip.  It is left
empty by this controller, so its default no-op action applies and the
pipeline behaves identically to a version without the table.  If you want
to install/remove a block manually, use simple_switch_CLI from a shell:

    simple_switch_CLI --thrift-port 9090 <<< "table_add tbl_block_ip block_source 10.1.1.1 =>"
    simple_switch_CLI --thrift-port 9090 <<< "table_delete tbl_block_ip <handle>"

P4 CPU header layout (45 bytes):
    offset  size  field
    0       1     reason                 (constant 0xAA)
    1       1     switch_id
    2..3    2     ingress_port (9b) + pad
    4..7    4     sender_ip
    8..13   6     sender_mac
    14..17  4     target_ip
    18..19  2     opcode
    20..23  4     reg_arp_total
    24..27  4     reg_arp_request
    28..31  4     reg_arp_reply
    32..35  4     reg_gratuitous
    36..39  4     reg_broadcast
    40      1     reg_sample_counter
    41..44  4     reg_self_mac_mismatch

13 ML features emitted per window (CSV order):
    1  arp_rate
    2  request_reply_imbalance
    3  src_ip_entropy
    4  unique_src_ip_count
    5  src_mac_entropy
    6  target_ip_entropy
    7  unique_target_ip_count
    8  broadcast_fraction
    9  gratuitous_fraction
   10  self_mac_mismatch_count
   11  delta_arp_rate
   12  new_ip_ratio
   13  cross_switch_spread
   + digests_received, top_src_ip, label

USAGE:
    sudo python3 controller.py \
        --interfaces s1-cpu1 s2-cpu1 s3-cpu1 s4-cpu1 s11-cpu1 \
        --label normal
"""

import os, sys, time, struct, math, socket, select
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
SO_RCVBUF_BYTES = 16 * 1024 * 1024
SHUTDOWN        = threading.Event()

# Linux AF_PACKET stats — used only to count kernel drops for diagnostics
SOL_PACKET        = 263
PACKET_STATISTICS = 6
TPACKET_STATS_FMT = "II"
TPACKET_STATS_LEN = struct.calcsize(TPACKET_STATS_FMT)

# ── CPU Header parser (45 bytes) ──────────────────────────────────────────────
CPU_FMT  = "!BB H 4s 6s 4s H IIIII BI"
CPU_SIZE = struct.calcsize(CPU_FMT)   # must be 45

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
        o                  = cls()
        o.switch_id        = f[1]
        o.ingress_port     = (f[2] & 0xFF80) >> 7
        o.sender_ip        = socket.inet_ntoa(f[3])
        o.sender_mac       = ":".join(f"{b:02x}" for b in f[4])
        o.target_ip        = socket.inet_ntoa(f[5])
        o.opcode           = f[6]
        o.reg_total        = f[7]
        o.reg_req          = f[8]
        o.reg_rep          = f[9]
        o.reg_grat         = f[10]
        o.reg_bcast        = f[11]
        o.reg_ctr          = f[12]
        o.reg_self_mismatch = f[13]
        return o

    def __repr__(self):
        return (f"<CPU sw={self.switch_id} src={self.sender_ip} "
                f"total={self.reg_total} selfmm={self.reg_self_mismatch}>")


def _read_packet_drops(sock) -> int:
    try:
        data = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, TPACKET_STATS_LEN)
        _tp_packets, tp_drops = struct.unpack(TPACKET_STATS_FMT, data)
        return tp_drops
    except OSError:
        return 0


# ══════════════════════════════════════════════════════════════════════════════
#  WINDOW AGGREGATOR — 13 features + digest count + top source IP
# ══════════════════════════════════════════════════════════════════════════════

class WindowAggregator:
    def __init__(self, window_sec, dataset_path, label_mode):
        self.window_sec    = window_sec
        self.dataset_path  = dataset_path
        self.label_mode    = label_mode
        self.lock          = threading.Lock()

        # Cross-window state (for temporal features)
        self._prev_src_ips  = set()
        self._prev_arp_rate = 0.0

        self._reset()
        self._init_csv()

    def _reset(self):
        # Register aggregates (summed across all digests in the window)
        self.agg_total   = 0
        self.agg_req     = 0
        self.agg_rep     = 0
        self.agg_grat    = 0
        self.agg_bcast   = 0
        self.agg_selfmm  = 0

        # Per-packet context lists
        self.sip_list    = []
        self.smac_list   = []
        self.tip_list    = []
        self.swid_list   = []

        # Diagnostics
        self.n_packetin   = 0
        self.window_drops = 0

        self.win_start    = time.time()

    def _init_csv(self):
        os.makedirs(os.path.dirname(self.dataset_path), exist_ok=True)
        write_hdr = not os.path.exists(self.dataset_path)
        self._f = open(self.dataset_path, "a", newline="")
        self._w = csv.writer(self._f)
        if write_hdr:
            self._w.writerow([
                "timestamp",
                # ── 13 ML features ───────────────────────────────────────
                "arp_rate",
                "request_reply_imbalance",
                "src_ip_entropy",
                "unique_src_ip_count",
                "src_mac_entropy",
                "target_ip_entropy",
                "unique_target_ip_count",
                "broadcast_fraction",
                "gratuitous_fraction",
                "self_mac_mismatch_count",
                "delta_arp_rate",
                "new_ip_ratio",
                "cross_switch_spread",
                # ── informational (not features) ─────────────────────────
                "digests_received",
                "top_src_ip",
                "label",
            ])
            self._f.flush()
        log.info(f"[CSV] {self.dataset_path}")

    # ── ingest ────────────────────────────────────────────────────────────

    def ingest(self, h: CpuHeader):
        with self.lock:
            self.agg_total   += h.reg_total
            self.agg_req     += h.reg_req
            self.agg_rep     += h.reg_rep
            self.agg_grat    += h.reg_grat
            self.agg_bcast   += h.reg_bcast
            self.agg_selfmm  += h.reg_self_mismatch

            self.sip_list.append(h.sender_ip)
            self.smac_list.append(h.sender_mac)
            self.tip_list.append(h.target_ip)
            self.swid_list.append(h.switch_id)

            self.n_packetin += 1

    def note_drop(self, n=1):
        if n <= 0:
            return
        with self.lock:
            self.window_drops += n

    def tick(self):
        with self.lock:
            if time.time() - self.win_start >= self.window_sec:
                self._flush()
                self._reset()

    # ── flush ─────────────────────────────────────────────────────────────

    def _flush(self):
        elapsed = max(time.time() - self.win_start, 0.001)

        # ── raw counter snapshots (for terminal print + CSV features) ────
        raw_total  = self.agg_total
        raw_req    = self.agg_req
        raw_rep    = self.agg_rep
        raw_grat   = self.agg_grat
        raw_bcast  = self.agg_bcast
        raw_selfmm = self.agg_selfmm

        # ── Feature 1: arp_rate ──────────────────────────────────────────
        arp_rate = round(raw_total / elapsed, 4)

        # ── Feature 2: request_reply_imbalance ───────────────────────────
        request_reply_imbalance = round(
            (raw_req - raw_rep) / (raw_req + raw_rep + 1), 4
        )

        # ── Feature 3: src_ip_entropy ────────────────────────────────────
        src_ip_entropy = round(self._entropy(self.sip_list), 4)

        # ── Feature 4: unique_src_ip_count ───────────────────────────────
        usip = set(self.sip_list)
        unique_src_ip_count = len(usip)

        # ── Feature 5: src_mac_entropy ───────────────────────────────────
        src_mac_entropy = round(self._entropy(self.smac_list), 4)

        # ── Feature 6: target_ip_entropy ─────────────────────────────────
        target_ip_entropy = round(self._entropy(self.tip_list), 4)

        # ── Feature 7: unique_target_ip_count ────────────────────────────
        unique_target_ip_count = len(set(self.tip_list))

        # ── Feature 8: broadcast_fraction ────────────────────────────────
        broadcast_fraction = round(raw_bcast / (raw_total + 1), 4)

        # ── Feature 9: gratuitous_fraction ───────────────────────────────
        gratuitous_fraction = round(raw_grat / (raw_total + 1), 4)

        # ── Feature 10: self_mac_mismatch_count ──────────────────────────
        self_mac_mismatch_count = raw_selfmm

        # ── Feature 11: delta_arp_rate ───────────────────────────────────
        delta_arp_rate = round(arp_rate - self._prev_arp_rate, 4)

        # ── Feature 12: new_ip_ratio ─────────────────────────────────────
        if usip:
            new_ip_ratio = round(
                len(usip - self._prev_src_ips) / len(usip), 4
            )
        else:
            new_ip_ratio = 0.0

        # ── Feature 13: cross_switch_spread ──────────────────────────────
        cross_switch_spread = len(set(self.swid_list))

        # ── Update cross-window state ────────────────────────────────────
        self._prev_src_ips  = usip.copy()
        self._prev_arp_rate = arp_rate

        # ── Digest count ─────────────────────────────────────────────────
        digests_received  = self.n_packetin
        drops_this_window = self.window_drops

        # ── Top source IP ────────────────────────────────────────────────
        if self.sip_list:
            ctr = collections.Counter(self.sip_list)
            top_src_ip, top_count = ctr.most_common(1)[0]
            top_share = round(top_count / len(self.sip_list), 4)
        else:
            top_src_ip, top_count, top_share = "-", 0, 0.0

        # ── CSV row (features + informational only) ──────────────────────
        label = 1 if self.label_mode == "attack" else 0
        ts    = datetime.now().isoformat(timespec="seconds")

        self._w.writerow([
            ts,
            arp_rate,
            request_reply_imbalance,
            src_ip_entropy,
            unique_src_ip_count,
            src_mac_entropy,
            target_ip_entropy,
            unique_target_ip_count,
            broadcast_fraction,
            gratuitous_fraction,
            self_mac_mismatch_count,
            delta_arp_rate,
            new_ip_ratio,
            cross_switch_spread,
            digests_received,
            top_src_ip,
            label,
        ])
        self._f.flush()

        # ── Terminal log — includes all raw counters ─────────────────────
        log.info(
            f"[WIN] {ts} | "
            f"digests={digests_received:4d} "
            f"total={raw_total:6d} "
            f"req={raw_req:6d} "
            f"rep={raw_rep:6d} "
            f"grat={raw_grat:5d} "
            f"bcast={raw_bcast:6d} "
            f"selfmm={raw_selfmm:3d} "
            f"drops={drops_this_window:3d} | "
            f"rate={arp_rate:8.2f}pps "
            f"imb={request_reply_imbalance:+.3f} "
            f"H_src={src_ip_entropy:5.3f} "
            f"uniq_src={unique_src_ip_count:3d} "
            f"H_mac={src_mac_entropy:5.3f} "
            f"H_tgt={target_ip_entropy:5.3f} "
            f"uniq_tgt={unique_target_ip_count:3d} | "
            f"bcast%={broadcast_fraction:.3f} "
            f"grat%={gratuitous_fraction:.3f} "
            f"drate={delta_arp_rate:+9.2f} "
            f"newip={new_ip_ratio:.3f} "
            f"spread={cross_switch_spread} | "
            f"top_src={top_src_ip} ({top_share*100:.1f}%, {top_count}pkts) | "
            f"label={'ATTACK' if label else 'normal'}"
        )

        # ── Prominent top-source line ────────────────────────────────────
        if top_count > 0:
            log.info(
                f"[TOP_SRC] {ts} | {top_src_ip}  "
                f"share={top_share*100:.1f}%  "
                f"count={top_count}  "
                f"digests={digests_received}"
            )

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
        with self.lock:
            if self.n_packetin > 0:
                self._flush()
        self._f.close()
        log.info("[CTRL] CSV closed.")


# ══════════════════════════════════════════════════════════════════════════════
#  SNIFFER
# ══════════════════════════════════════════════════════════════════════════════

_agg: WindowAggregator = None


def _open_raw_socket(iface: str):
    try:
        s = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL),
        )
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SO_RCVBUF_BYTES)
        except OSError:
            pass
        s.bind((iface, ETH_P_ALL))
        s.setblocking(False)
        return s
    except OSError as e:
        log.debug(f"[SNIFF] {iface} open failed errno={e.errno}: {e}")
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
        log.info(f"[SNIFF] Capturing on {iface} (ETH_P_ALL, rcvbuf={SO_RCVBUF_BYTES})")

        _read_packet_drops(sock)

        try:
            while not SHUTDOWN.is_set():
                r, _, _ = select.select([sock], [], [], 0.5)

                if not r:
                    drops = _read_packet_drops(sock)
                    if drops:
                        _agg.note_drop(drops)
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
                    _agg.note_drop(drops)

        except OSError as e:
            log.warning(f"[SNIFF] {iface} lost (errno={e.errno}): {e}. Reconnecting...")
        except Exception as e:
            log.warning(f"[SNIFF] {iface} error: {e}. Reconnecting...")
        finally:
            try:
                sock.close()
            except Exception:
                pass

        if SHUTDOWN.wait(IFACE_RETRY_SEC):
            return


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global _agg

    ap = argparse.ArgumentParser(
        description="ARP Flood Detection Controller (monitoring only, 13 features)"
    )
    ap.add_argument("--interfaces", "-i", nargs="+", required=True)
    ap.add_argument("--window",  "-w", type=int, default=WINDOW_SEC)
    ap.add_argument("--label",   "-l",
                    choices=["normal", "attack"], default="normal",
                    help="normal => label 0 in CSV, attack => label 1 in CSV")
    ap.add_argument("--dataset", "-d", default=DATASET_PATH)

    args = ap.parse_args()

    if os.geteuid() != 0:
        log.error("This controller needs root (AF_PACKET requires CAP_NET_RAW).")
        sys.exit(1)

    log.info("=" * 72)
    log.info("  ARP Flood Detection Controller — monitoring only, 13 features")
    log.info(f"  Interfaces : {args.interfaces}")
    log.info(f"  Window     : {args.window}s")
    log.info(f"  Label      : {args.label}  (SIGUSR1 to toggle)")
    log.info(f"  ML dataset : {args.dataset}")
    log.info(f"  CPU_SIZE   : {CPU_SIZE} bytes (CPU_FMT = {CPU_FMT!r})")
    log.info("  Blocking   : disabled (no P4 table writes from this controller)")
    log.info("=" * 72)

    _agg = WindowAggregator(args.window, args.dataset, args.label)

    # ── Sniff threads ────────────────────────────────────────────────────
    threads = []
    for iface in args.interfaces:
        t = threading.Thread(target=_sniff_thread, args=(iface,),
                             name=f"sniff-{iface}", daemon=True)
        t.start()
        threads.append(t)

    # ── Ticker thread ────────────────────────────────────────────────────
    def _ticker():
        while not SHUTDOWN.is_set():
            if SHUTDOWN.wait(0.5):
                return
            _agg.tick()
    threading.Thread(target=_ticker, name="ticker", daemon=True).start()

    # ── SIGUSR1 toggles label ────────────────────────────────────────────
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

#!/usr/bin/env python3
"""
clean_combine.py — 5-step pipeline producing raw + cleaned datasets.

Step A — RAW COMBINE (nothing removed):
    dataset/combined_normal_raw.csv   24 cols, all normal rows
    dataset/combined_attack_raw.csv   24 cols, all attack rows

Step B — CLEAN PER CLASS (dedup + idle removal + trim to 18):
    dataset/clean_normal.csv          18 cols
    dataset/clean_attack.csv          18 cols

Step C — COMBINE + SHUFFLE:
    dataset/arp_dataset_clean.csv     18 cols, shuffled
"""
import csv, os, sys, random
from collections import Counter

# ── Schemas ──────────────────────────────────────────────────────────
RAW_COLS = [
    "timestamp",
    "arp_rate", "request_reply_imbalance",
    "src_ip_entropy", "unique_src_ip_count",
    "src_mac_entropy", "target_ip_entropy", "unique_target_ip_count",
    "broadcast_fraction", "gratuitous_fraction",
    "self_mac_mismatch_count", "delta_arp_rate",
    "new_ip_ratio", "cross_switch_spread",
    "top_port_share", "unique_host_ports",
    "top_sw_id", "top_ingress_port", "top_port_composite",
    "port_pkts_raw",
    "digests_received", "top_src_ip",
    "top_src_ip_share",
    "label",
]

KEEP_COLS = [
    "timestamp",
    "arp_rate", "request_reply_imbalance",
    "src_ip_entropy", "unique_src_ip_count",
    "src_mac_entropy", "target_ip_entropy", "unique_target_ip_count",
    "broadcast_fraction", "gratuitous_fraction",
    "self_mac_mismatch_count", "delta_arp_rate",
    "new_ip_ratio", "cross_switch_spread",
    "top_port_share", "unique_host_ports",
    "top_src_ip_share",
    "label",
]

REMOVED_COLS = [
    "top_sw_id", "top_ingress_port", "top_port_composite",
    "port_pkts_raw", "digests_received", "top_src_ip",
]

assert len(RAW_COLS) == 24
assert len(KEEP_COLS) == 18
assert set(KEEP_COLS) | set(REMOVED_COLS) == set(RAW_COLS)
assert set(KEEP_COLS) & set(REMOVED_COLS) == set()

BASE = os.path.dirname(os.path.abspath(__file__))

NORMAL_INPUTS = [
    os.path.join(BASE, "dataset",         "arp_dataset_normal.csv"),
    os.path.join(BASE, "correct dataset", "arp_dataset_normal.csv"),
]
ATTACK_INPUTS = [
    os.path.join(BASE, "dataset",         "arp_dataset_attack.csv"),
    os.path.join(BASE, "correct dataset", "arp_dataset_attack.csv"),
]

OUT_RAW_NORMAL   = os.path.join(BASE, "dataset", "combined_normal_raw.csv")
OUT_RAW_ATTACK   = os.path.join(BASE, "dataset", "combined_attack_raw.csv")
OUT_CLEAN_NORMAL = os.path.join(BASE, "dataset", "clean_normal.csv")
OUT_CLEAN_ATTACK = os.path.join(BASE, "dataset", "clean_attack.csv")
OUT_COMBINED     = os.path.join(BASE, "dataset", "arp_dataset_clean.csv")


# ── Helpers ──────────────────────────────────────────────────────────
def load_file(path):
    if not os.path.exists(path):
        return None, []
    try:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            return reader.fieldnames or [], list(reader)
    except Exception as e:
        print(f"  ⚠️  read failed {path}: {e}")
        return None, []


def is_idle(r):
    try:
        return float(r["arp_rate"]) == 0.0 and int(r["digests_received"]) == 0
    except (ValueError, KeyError, TypeError):
        return False


def full_fingerprint(r):
    return tuple(r.get(c, "") for c in RAW_COLS)


def trim(r):
    return {c: r.get(c, "") for c in KEEP_COLS}


def save_csv(path, rows, columns):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    size_kb = os.path.getsize(path) / 1024
    print(f"    ✓ {path}  ({len(rows)} rows, {size_kb:.1f} KB)")


def raw_combine(label, input_paths):
    """Concatenate all files for a class — no dedup, no removal, 24 cols."""
    all_rows = []
    files_report = []
    for path in input_paths:
        if not os.path.exists(path):
            files_report.append((os.path.relpath(path, BASE), 0, "missing"))
            continue
        rel = os.path.relpath(path, BASE)
        header, rows = load_file(path)
        if header is None:
            files_report.append((rel, 0, "unreadable"))
            continue
        if header != RAW_COLS:
            files_report.append((rel, len(rows), "schema mismatch"))
            continue
        # Filter by label defensively (skip rows with wrong label)
        kept = [r for r in rows if str(r.get("label","")).strip() == label]
        all_rows.extend(kept)
        files_report.append((rel, len(kept), "ok"))

    return all_rows, files_report


def clean_class(rows, label):
    """Dedup + remove idle + trim to 18 cols."""
    # Dedup
    seen = set()
    deduped = []
    for r in rows:
        fp = full_fingerprint(r)
        if fp in seen:
            continue
        seen.add(fp)
        deduped.append(r)
    n_dupes = len(rows) - len(deduped)

    # Remove idle
    non_idle = [r for r in deduped if not is_idle(r)]
    n_idle = len(deduped) - len(non_idle)

    # Trim columns
    trimmed = [trim(r) for r in non_idle]

    return trimmed, {
        "input": len(rows),
        "deduped": len(deduped),
        "duplicates_removed": n_dupes,
        "idle_removed": n_idle,
        "final": len(trimmed),
    }


def feature_stats(rows, cols):
    out = {}
    for c in cols:
        vals = []
        for r in rows:
            try: vals.append(float(r[c]))
            except (ValueError, KeyError, TypeError): pass
        if not vals:
            out[c] = (0.0, 0.0, 0.0)
            continue
        vals.sort()
        out[c] = (vals[len(vals)//2], vals[int(0.95*len(vals))], vals[-1])
    return out


# ── Main pipeline ────────────────────────────────────────────────────
def main():
    print("═" * 72)
    print("  CLEAN & COMBINE — 5-step pipeline")
    print("═" * 72)

    # ══════════════════════════════════════════════════════════════
    # STEP A — RAW COMBINE (nothing removed)
    # ══════════════════════════════════════════════════════════════
    print("\n" + "━" * 72)
    print("  STEP A — RAW COMBINE (no dedup, no removal, 24 columns)")
    print("━" * 72)

    print("\n[A.1] Combining normal files …")
    raw_normal, n_rep = raw_combine("0", NORMAL_INPUTS)
    for name, cnt, status in n_rep:
        flag = "✓" if status == "ok" else "⚠️"
        print(f"    {flag} {name}: {cnt} rows [{status}]")
    print(f"    TOTAL: {len(raw_normal)} rows")
    save_csv(OUT_RAW_NORMAL, raw_normal, RAW_COLS)

    print("\n[A.2] Combining attack files …")
    raw_attack, a_rep = raw_combine("1", ATTACK_INPUTS)
    for name, cnt, status in a_rep:
        flag = "✓" if status == "ok" else "⚠️"
        print(f"    {flag} {name}: {cnt} rows [{status}]")
    print(f"    TOTAL: {len(raw_attack)} rows")
    save_csv(OUT_RAW_ATTACK, raw_attack, RAW_COLS)

    print(f"\n    Raw files have {len(RAW_COLS)} columns each — nothing dropped")

    # ══════════════════════════════════════════════════════════════
    # STEP B — CLEAN PER CLASS
    # ══════════════════════════════════════════════════════════════
    print("\n" + "━" * 72)
    print("  STEP B — CLEAN PER CLASS (dedup + idle removal + trim to 18)")
    print("━" * 72)

    print("\n[B.1] Cleaning normal class …")
    clean_normal, nst = clean_class(raw_normal, "0")
    print(f"    Input          : {nst['input']} rows (24 cols)")
    print(f"    After dedup    : {nst['deduped']} rows "
          f"(removed {nst['duplicates_removed']} duplicates)")
    print(f"    After idle rem : {nst['final']} rows "
          f"(removed {nst['idle_removed']} idle)")
    save_csv(OUT_CLEAN_NORMAL, clean_normal, KEEP_COLS)

    print("\n[B.2] Cleaning attack class …")
    clean_attack, ast = clean_class(raw_attack, "1")
    print(f"    Input          : {ast['input']} rows (24 cols)")
    print(f"    After dedup    : {ast['deduped']} rows "
          f"(removed {ast['duplicates_removed']} duplicates)")
    print(f"    After idle rem : {ast['final']} rows "
          f"(removed {ast['idle_removed']} idle)")
    save_csv(OUT_CLEAN_ATTACK, clean_attack, KEEP_COLS)

    # ══════════════════════════════════════════════════════════════
    # STEP C — COMBINE + SHUFFLE
    # ══════════════════════════════════════════════════════════════
    print("\n" + "━" * 72)
    print("  STEP C — COMBINE + SHUFFLE")
    print("━" * 72)

    combined = clean_normal + clean_attack
    random.seed(42)
    random.shuffle(combined)

    n0 = len(clean_normal)
    n1 = len(clean_attack)
    n = len(combined)

    print(f"\n[C.1] Label distribution:")
    print(f"    normal (0): {n0:6d}  ({100*n0/max(n,1):5.1f}%)")
    print(f"    attack (1): {n1:6d}  ({100*n1/max(n,1):5.1f}%)")
    print(f"    Total     : {n:6d}")
    if n0 and n1:
        ratio = n0 / n1
        v = "✅" if 0.5 <= ratio <= 2.0 else "⚠️ "
        print(f"    {v} normal:attack = {ratio:.2f}:1")

    print(f"\n[C.2] Saving combined shuffled dataset …")
    save_csv(OUT_COMBINED, combined, KEEP_COLS)

    # ══════════════════════════════════════════════════════════════
    # Summary — feature stats + attack signatures
    # ══════════════════════════════════════════════════════════════
    FEATURES = KEEP_COLS[1:-1]
    n_stat = feature_stats(clean_normal, FEATURES)
    a_stat = feature_stats(clean_attack, FEATURES)

    print("\n" + "━" * 72)
    print("  FEATURE STATISTICS (clean data)")
    print("━" * 72)
    print(f"\n  {'feature':28s}  {'norm p50':>9s}  {'atk p50':>9s}  "
          f"{'norm p95':>9s}  {'atk p95':>9s}  sep?")
    print(f"  {'-'*28}  {'-'*9}  {'-'*9}  {'-'*9}  {'-'*9}  ----")
    separating = 0
    for c in FEATURES:
        np50, np95, _ = n_stat[c]
        ap50, ap95, _ = a_stat[c]
        if np95 > 0:
            ratio = ap95 / np95
            sep = ratio > 1.5 or ratio < 0.67
        else:
            sep = ap95 > 0
        if sep: separating += 1
        m = "✅" if sep else "—"
        print(f"  {c:28s}  {np50:9.3f}  {ap50:9.3f}  "
              f"{np95:9.3f}  {ap95:9.3f}  {m}")
    print(f"\n  {separating}/{len(FEATURES)} features separate the classes")

    # ══════════════════════════════════════════════════════════════
    # Final summary
    # ══════════════════════════════════════════════════════════════
    print("\n" + "═" * 72)
    print("  FILES WRITTEN")
    print("═" * 72)
    print(f"  RAW (24 cols, nothing removed):")
    print(f"    {OUT_RAW_NORMAL}")
    print(f"    {OUT_RAW_ATTACK}")
    print()
    print(f"  CLEAN (18 cols, deduped + idle-removed):")
    print(f"    {OUT_CLEAN_NORMAL}      ({n0} rows)")
    print(f"    {OUT_CLEAN_ATTACK}      ({n1} rows)")
    print(f"    {OUT_COMBINED}          ({n} rows)")
    print()
    print(f"  Column delta: {len(RAW_COLS)} → {len(KEEP_COLS)} (dropped {len(REMOVED_COLS)})")
    print(f"  Dropped: {REMOVED_COLS}")

    print("\n  Next step:")
    print(f"    python3 training/train_model.py {OUT_COMBINED} models/arp_rf.pkl")
    print("═" * 72)


if __name__ == "__main__":
    main()

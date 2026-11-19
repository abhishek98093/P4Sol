#!/usr/bin/env python3
"""
plot_latency.py — read action_latency.csv, draw a 2-bar chart:
    bar 1 = mean model_latency_ms
    bar 2 = mean rule_install_ms
Values are annotated on top of each bar.

Usage:
    python3 plot_latency.py                       # default: action_latency.csv
    python3 plot_latency.py my_latency.csv        # custom path
    python3 plot_latency.py --show                # also open the figure
"""
import argparse, os, sys
import pandas as pd
import matplotlib.pyplot as plt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default="action_latency.csv")
    ap.add_argument("--out", default="latency_bar.png")
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        sys.exit(f"[!] {args.csv} not found")

    df = pd.read_csv(args.csv)
    if df.empty:
        sys.exit("[!] CSV has no rows")

    # model latency: present on every attack-flagged window
    model_vals = pd.to_numeric(df["model_latency_ms"], errors="coerce").dropna()

    # rule install latency: only present on rows where a rule was actually installed
    rule_vals = pd.to_numeric(df["rule_install_ms"], errors="coerce").dropna()

    if model_vals.empty:
        sys.exit("[!] no model_latency_ms values found")

    m_mean = float(model_vals.mean())
    r_mean = float(rule_vals.mean()) if not rule_vals.empty else 0.0

    # ── text summary ─────────────────────────────────────────────
    print(f"[+] file: {args.csv}")
    print(f"[+] attack-flagged windows : {len(model_vals)}")
    print(f"[+] rules actually installed: {len(rule_vals)}")
    print()
    print(f"  mean model latency       : {m_mean:8.3f} ms")
    if not rule_vals.empty:
        print(f"  mean rule install latency: {r_mean:8.3f} ms")
        print(f"  mean total (approx)      : {m_mean + r_mean:8.3f} ms")
    else:
        print(f"  mean rule install latency:      — (no rules installed in this run)")
    print()

    # ── plot ─────────────────────────────────────────────────────
    labels = ["model latency", "rule install latency"]
    values = [m_mean, r_mean]
    colors = ["#2ca02c", "#d62728"]

    fig, ax = plt.subplots(figsize=(7.5, 5))
    bars = ax.bar(labels, values, color=colors, width=0.55,
                  edgecolor="black", linewidth=0.6)

    # annotate value on top of each bar
    for bar, v in zip(bars, values):
        if v == 0 and len(rule_vals) == 0:
            txt = "n/a"
        else:
            txt = f"{v:.2f} ms"
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                txt,
                ha="center", va="bottom",
                fontsize=11, fontweight="bold")

    ax.set_ylabel("latency (ms)")
    ax.set_title("Detection vs Mitigation Latency (mean)", fontsize=13)
    ax.grid(True, axis="y", alpha=0.3, linestyle="--", linewidth=0.6)

    ymax = max(values) if max(values) > 0 else 1
    ax.set_ylim(0, ymax * 1.20)          # head-room for annotation

    # show count of windows in a subtitle
    subtitle = (f"model n={len(model_vals)}   "
                f"rule install n={len(rule_vals)}")
    fig.text(0.5, 0.02, subtitle, ha="center", fontsize=9, color="dimgray")

    plt.tight_layout(rect=[0, 0.04, 1, 1])
    plt.savefig(args.out, dpi=150)
    print(f"[+] wrote {args.out}")

    if args.show:
        plt.show()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
compare_perf.py — baseline vs P4Sol column-means bar charts.

 - drops any window where window_digests == 0 (idle windows)
 - one bar-chart subplot per numeric column
 - value annotated on top of each bar
 - labels: "baseline" (red) and "P4Sol" (green, = current)
"""
import argparse, glob, os, sys
import pandas as pd
import matplotlib.pyplot as plt

SKIP_COLS    = {"window_start", "mode", "label", "model_pred"}
DIGEST_COL   = "window_digests"          # rows with this == 0 are dropped
LABEL_BASE   = "baseline"
LABEL_CUR    = "P4Guard"                   # display name for the current run


def discover(prefix):
    for p in (f"{prefix}_perf_*.csv", f"dataset/{prefix}_perf_*.csv"):
        hits = sorted(glob.glob(p))
        if hits:
            return hits[-1]
    return None


def load_and_filter(path):
    df = pd.read_csv(path)
    before = len(df)
    if DIGEST_COL in df.columns:
        df = df[df[DIGEST_COL] > 0].reset_index(drop=True)
    print(f"  {os.path.basename(path)}: {before} rows -> {len(df)} after "
          f"dropping {DIGEST_COL} == 0")
    return df


def numeric_cols(df):
    return [c for c in df.columns
            if c not in SKIP_COLS and pd.api.types.is_numeric_dtype(df[c])]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline", nargs="?")
    ap.add_argument("current",  nargs="?")
    ap.add_argument("--cols", nargs="+", default=None)
    ap.add_argument("--out",  default="perf_column_comparison.png")
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    b_path = args.baseline or discover("baseline")
    c_path = args.current  or discover("current")
    if not b_path or not c_path:
        sys.exit("Could not locate both perf CSVs.")

    print(f"[+] baseline = {b_path}")
    print(f"[+] current  = {c_path}")

    b_df = load_and_filter(b_path)
    c_df = load_and_filter(c_path)

    if b_df.empty or c_df.empty:
        sys.exit("After filtering, one of the CSVs has no rows left. "
                 "Check the digest column exists and is non-zero.")

    cols = [c for c in numeric_cols(b_df) if c in c_df.columns]
    if args.cols:
        cols = [c for c in args.cols if c in cols]
    if not cols:
        sys.exit("No numeric columns to plot.")

    b_means = {c: float(b_df[c].mean()) for c in cols}
    c_means = {c: float(c_df[c].mean()) for c in cols}

    # ── text table ────────────────────────────────────────────────
    print()
    print(f"{'column':<32}{LABEL_BASE:>14}{LABEL_CUR:>14}{'base/P4Sol':>14}")
    print("-" * 74)
    for c in cols:
        b, k = b_means[c], c_means[c]
        ratio = (b / k) if k else float("inf")
        print(f"{c:<32}{b:>14.4f}{k:>14.4f}{ratio:>14.3f}")
    print()

    # ── bar-chart grid ────────────────────────────────────────────
    n     = len(cols)
    ncols = 4
    nrows = (n + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols,
                             figsize=(ncols * 4.2, max(3, nrows * 3.2)),
                             squeeze=False)

    for i, col in enumerate(cols):
        r, k = divmod(i, ncols)
        ax = axes[r][k]

        vals   = [b_means[col], c_means[col]]
        labels = [LABEL_BASE,  LABEL_CUR]
        colors = ["#d62728",   "#2ca02c"]

        bars = ax.bar(labels, vals, color=colors, width=0.6)

        # annotate value on top of each bar
        for bar, v in zip(bars, vals):
            if v == 0:
                txt = "0"
            elif abs(v) >= 1000:
                txt = f"{v:,.0f}"
            elif abs(v) >= 1:
                txt = f"{v:.2f}"
            else:
                txt = f"{v:.3g}"
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height(),
                    txt,
                    ha="center", va="bottom",
                    fontsize=8, fontweight="bold")

        ax.set_title(col, fontsize=9)
        ax.tick_params(labelsize=8)
        ax.grid(True, axis="y", alpha=0.3, linestyle="--", linewidth=0.5)

        # small head-room so the annotation isn't clipped
        ymax = max(vals) if max(vals) > 0 else 1
        ax.set_ylim(0, ymax * 1.18)

    # hide unused cells
    for j in range(n, nrows * ncols):
        r, k = divmod(j, ncols)
        axes[r][k].axis("off")

    fig.suptitle(f"Per-column means (windows with {DIGEST_COL} > 0)\n"
                 f"{LABEL_BASE} (red)  vs  {LABEL_CUR} (green)",
                 fontsize=13)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(args.out, dpi=150)
    print(f"[+] wrote {args.out}")
    if args.show:
        plt.show()


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# run_all.sh — full 2-hour dataset generation (1h normal, 1h attack).
# Handles controller lifecycle too. Just answer the password prompts.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(cd "${DIR}/.." && pwd)"
DATASET_DIR="${PROJECT}/dataset"
CTRL="${PROJECT}/controller/controller.py"
IFACES="s1-cpu1 s2-cpu1 s3-cpu1 s4-cpu1 s11-cpu1"

mkdir -p "$DATASET_DIR"

echo "============================================================"
echo " DATASET GENERATION — Normal (1h) + Attack (1h)"
echo "============================================================"
echo ""
echo "This will:"
echo "  1. Start controller (label=normal), run normal + spikes for 1h"
echo "  2. Stop controller, start fresh (label=attack), run attacks for 1h"
echo "  3. Combine, shuffle, verify"
echo ""
read -p "Press Enter to begin NORMAL phase (Ctrl+C to abort)..."

# ── Phase 1: normal ───────────────────────────────────────────────────
rm -f "$DATASET_DIR/arp_dataset_normal.csv"
sudo python3 "$CTRL" --interfaces $IFACES --label normal \
    --dataset "$DATASET_DIR/arp_dataset_normal.csv" &
CTRL_PID=$!
sleep 2

bash "${DIR}/run_normal_1hr.sh" 3600 &
NORM_PID=$!
bash "${DIR}/legitimate_spikes.sh" 3600 180 &
SPK_PID=$!

wait $NORM_PID $SPK_PID
kill -INT $CTRL_PID 2>/dev/null; wait $CTRL_PID 2>/dev/null || true
echo "[+] Normal phase done: $(wc -l < "$DATASET_DIR/arp_dataset_normal.csv") rows"

# ── Phase 2: attack ───────────────────────────────────────────────────
echo ""
read -p "Press Enter to begin ATTACK phase (Ctrl+C to abort)..."

rm -f "$DATASET_DIR/arp_dataset_attack.csv"
sudo python3 "$CTRL" --interfaces $IFACES --label attack \
    --dataset "$DATASET_DIR/arp_dataset_attack.csv" &
CTRL_PID=$!
sleep 2

bash "${DIR}/run_attack_1hr.sh" 3600
kill -INT $CTRL_PID 2>/dev/null; wait $CTRL_PID 2>/dev/null || true
echo "[+] Attack phase done: $(wc -l < "$DATASET_DIR/arp_dataset_attack.csv") rows"

# ── Phase 3: combine ──────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " COMBINING"
echo "============================================================"
head -1 "$DATASET_DIR/arp_dataset_normal.csv" > "$DATASET_DIR/arp_dataset_final.csv"
{ tail -n +2 "$DATASET_DIR/arp_dataset_normal.csv"
  tail -n +2 "$DATASET_DIR/arp_dataset_attack.csv"; } | shuf \
  >> "$DATASET_DIR/arp_dataset_final.csv"

echo "Final rows: $(wc -l < "$DATASET_DIR/arp_dataset_final.csv")"
echo "Label counts:"
tail -n +2 "$DATASET_DIR/arp_dataset_final.csv" | awk -F, '{print $NF}' \
  | sort | uniq -c
echo ""
echo "[+] Ready to train:"
echo "    python3 training/train_model.py $DATASET_DIR/arp_dataset_final.csv models/arp_rf.pkl"

#!/usr/bin/env bash
# run_attack_1hr.sh — 60 min structured to cover EVERY attack pattern.
#
#   Block 1  → 1-to-1              (flood_basic)
#   Block 2  → 1-to-many           (flood_rotating, 60 targets)
#   Block 3  → many-to-1 (true)    (flood_target from 3 real hosts)
#   Block 4  → many-to-many (true) (5 hosts → 5 DIFFERENT victims)
#   Block 5  → identity spoofing   (flood_mac → flood_ip → flood_both)
#   Block 6  → poison 1-to-1       (poison_victim)
#   Block 7  → poison 1-to-all     (poison_gateway)
#   Block 8  → MITM pairs          (mitm_pair)
#   Block 9  → two-phase           (scan_then_flood)
#   Block 10 → chaos               (storm)
set -u
DURATION="${1:-3600}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATK_PY="${DIR}/attack_traffic.py"
LOGDIR="/tmp"
[[ ! -f "$ATK_PY" ]] && { echo "ERROR: $ATK_PY not found" >&2; exit 1; }

N_BLOCKS=10
SLICE=$((DURATION / N_BLOCKS))
[[ $SLICE -lt 60 ]] && SLICE=60

get_pid() {
  local h="$1"
  for f in "/tmp/${h}.pid" "/tmp/mn.${h}.pid"; do
    [[ -f "$f" ]] && { cat "$f"; return 0; }
  done
  pgrep -f "mininet:${h}$" | head -1
}

launch() {
  local host=$1 mode=$2 target=$3 pps=$4
  local pid=$(get_pid "$host"); [[ -z "$pid" ]] && return 1
  mnexec -a "$pid" python3 "$ATK_PY" \
    --iface "${host}-eth0" --mode "$mode" \
    --duration "$SLICE" --pps "$pps" \
    ${target:+--target "$target"} \
    >"${LOGDIR}/atk_${host}_${mode}.log" 2>&1 &
}

run_block() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " [$(date +%H:%M:%S)] $1   (${SLICE}s)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

echo "============================================================"
echo " 1-HOUR STRUCTURED ATTACK   duration=${DURATION}s   slice=${SLICE}s"
echo "============================================================"

# ── Block 1: 1-to-1 ─────────────────────────────────────────────────
run_block "1-to-1: flood_basic (h1 → 10.2.1.1)"
launch h1 flood_basic 10.2.1.1 400
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 2: 1-to-many ──────────────────────────────────────────────
run_block "1-to-many: flood_rotating (h1 → all 60 hosts)"
launch h1 flood_rotating "" 300
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 3: many-to-1 (true) ───────────────────────────────────────
run_block "many-to-1: flood_target (h1+h16+h31 → 10.2.1.1)"
launch h1  flood_target 10.2.1.1 300
launch h16 flood_target 10.2.1.1 300
launch h31 flood_target 10.2.1.1 300
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 4: many-to-many (true) ────────────────────────────────────
run_block "many-to-many: 5 real hosts → 5 DIFFERENT victims"
launch h1  flood_basic 10.2.1.1 200
launch h5  flood_basic 10.3.1.1 200
launch h16 flood_basic 10.4.1.1 200
launch h31 flood_basic 10.1.1.1 200
launch h46 flood_basic 10.2.2.1 200
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 5: identity spoofing (rotate sub-modes) ───────────────────
run_block "identity spoofing: flood_mac → flood_ip → flood_both"
SUB=$((SLICE / 3))
launch h1  flood_mac  10.2.1.1 300
sleep $SUB; pkill -f attack_traffic.py 2>/dev/null; sleep 1
launch h16 flood_ip   10.2.1.1 300
sleep $SUB; pkill -f attack_traffic.py 2>/dev/null; sleep 1
launch h31 flood_both 10.2.1.1 300
sleep $((SLICE - 2*SUB)); pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 6: poison 1-to-1 ──────────────────────────────────────────
run_block "poison 1-to-1: poison_victim (h1+h5 poison two victims)"
launch h1 poison_victim 10.1.3.1 200
launch h5 poison_victim 10.1.5.1 200
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 7: poison 1-to-all ────────────────────────────────────────
run_block "poison 1-to-all: poison_gateway (h1+h16 impersonate gateway)"
launch h1  poison_gateway "" 200
launch h16 poison_gateway "" 200
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 8: MITM pairs ─────────────────────────────────────────────
run_block "MITM pairs: mitm_pair ×2"
launch h1 mitm_pair 10.1.3.1 150
launch h2 mitm_pair 10.1.6.1 150
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 9: two-phase ──────────────────────────────────────────────
run_block "two-phase: scan_then_flood (h1)"
launch h1 scan_then_flood "" 500
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

# ── Block 10: chaos ─────────────────────────────────────────────────
run_block "chaos: storm (h7 rotates modes every 3s)"
launch h7 storm "" 300
sleep "$SLICE"; pkill -f attack_traffic.py 2>/dev/null; sleep 2

pkill -f attack_traffic.py 2>/dev/null || true
echo ""
echo "============================================================"
echo " 1-HOUR ATTACK DONE — 10 patterns covered"
echo "============================================================"

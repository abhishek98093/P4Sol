#!/usr/bin/env bash
# run_normal_1hr.sh — 1 hour of realistic normal traffic across 30 hosts.
# Mixed intensities: normal + busy, varied roles.
set -u
DURATION="${1:-3600}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NORMAL_PY="${DIR}/normal_traffic.py"
LOGDIR="/tmp"
[[ ! -f "$NORMAL_PY" ]] && { echo "ERROR: $NORMAL_PY not found" >&2; exit 1; }

HOSTS=(h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 h14 h15)

get_pid() {
  local h="$1"
  for f in "/tmp/${h}.pid" "/tmp/mn.${h}.pid"; do
    [[ -f "$f" ]] && { cat "$f"; return 0; }
  done
  pgrep -f "mininet:${h}$" | head -1
}

echo "============================================================"
echo " 1-HOUR NORMAL TRAFFIC   duration=${DURATION}s   hosts=${#HOSTS[@]}"
echo "============================================================"

idx=0
for h in "${HOSTS[@]}"; do
  pid=$(get_pid "$h"); [[ -z "$pid" ]] && { echo "  [$h] SKIP"; continue; }
  case $((idx % 4)) in
    0) role=server ;;
    1) role=peer ;;
    *) role=client ;;
  esac
  case $((idx % 3)) in
    0) intensity=normal ;;
    1) intensity=normal ;;
    2) intensity=busy ;;
  esac
  echo "  [$h] role=${role} intensity=${intensity}"
  mnexec -a "$pid" python3 "$NORMAL_PY" \
    --iface "${h}-eth0" --role "$role" \
    --intensity "$intensity" --duration "$DURATION" \
    >"${LOGDIR}/nt_${h}.log" 2>&1 &
  idx=$((idx + 1))
done
echo "[run_normal_1hr] launched ${idx} hosts, waiting ${DURATION}s..."
wait
echo "[run_normal_1hr] done."

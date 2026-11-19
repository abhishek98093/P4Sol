#!/usr/bin/env bash
# legitimate_spikes.sh — legitimate ARP bursts that must NOT be classified as attacks.
# Types rotate: login storm, monitoring sweep, gratuitous ARP burst.
# Run in parallel with run_normal_1hr.sh.
set -u
DURATION="${1:-3600}"
INTERVAL="${2:-180}"
LOGDIR="/tmp"

HOSTS=(h2 h4 h6 h8 h10 h12 h14 h17 h19 h21 h23 h25 h27 h29 h32)

get_pid() {
  local h="$1"
  for f in "/tmp/${h}.pid" "/tmp/mn.${h}.pid"; do
    [[ -f "$f" ]] && { cat "$f"; return 0; }
  done
  pgrep -f "mininet:${h}$" | head -1
}

spike_login() {
  for h in "${HOSTS[@]}"; do
    pid=$(get_pid "$h"); [[ -z "$pid" ]] && continue
    mnexec -a "$pid" bash -c '
      for i in 1 2 3; do
        sw=$((RANDOM % 4 + 1)); j=$((RANDOM % 15 + 1))
        ping -c 1 -W 1 "10.${sw}.${j}.1" >/dev/null 2>&1
      done
    ' >/dev/null 2>&1 &
  done
  wait
}

spike_sweep() {
  for h in "${HOSTS[@]:0:5}"; do
    pid=$(get_pid "$h"); [[ -z "$pid" ]] && continue
    mnexec -a "$pid" bash -c '
      for sw in 1 2 3 4; do
        for j in 1 5 10 14; do
          ping -c 1 -W 1 "10.${sw}.${j}.1" >/dev/null 2>&1
        done
      done
    ' >/dev/null 2>&1 &
  done
  wait
}

spike_grarp() {
  for h in "${HOSTS[@]}"; do
    pid=$(get_pid "$h"); [[ -z "$pid" ]] && continue
    mnexec -a "$pid" bash -c '
      ip=$(ip -4 addr show | awk "/inet /{gsub(/\/.*/,\"\",\$2);print \$2;exit}")
      command -v arping >/dev/null && arping -c 1 -A -I "$1" "$ip" >/dev/null 2>&1
    ' "${h}-eth0" >/dev/null 2>&1 &
  done
  wait
}

TYPES=(login sweep grarp)
T_END=$(( $(date +%s) + DURATION ))
n=0
echo "============================================================"
echo " LEGITIMATE SPIKES   duration=${DURATION}s   interval=${INTERVAL}s"
echo "============================================================"
while [[ $(date +%s) -lt $T_END ]]; do
  t="${TYPES[$((n % 3))]}"
  echo "[$(date +%H:%M:%S)] spike #$((n+1)) → ${t}"
  case "$t" in
    login) spike_login ;;
    sweep) spike_sweep ;;
    grarp) spike_grarp ;;
  esac
  echo "[$(date +%H:%M:%S)] spike done, next in ${INTERVAL}s"
  n=$((n + 1))
  sleep "$INTERVAL"
done
echo "[legitimate_spikes] done."

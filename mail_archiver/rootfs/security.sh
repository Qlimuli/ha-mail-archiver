#!/bin/bash
# ClamAV security helper for ha-mail-archiver
set -uo pipefail

log() { echo "[mail-archiver:security] $*"; }

OPTIONS="${OPTIONS_FILE:-/data/options.json}"
[[ -f "$OPTIONS" ]] || OPTIONS=/tmp/options.json

cfg() { jq -r "$1" "$OPTIONS" 2>/dev/null; }

VIRUS_SCAN="$(cfg '.security_virus_scan // true')"
QUARANTINE="$(cfg '.security_quarantine // true')"
UPDATE_SIG="$(cfg '.security_update_signatures_on_start // true')"
SCAN_ON_START="$(cfg '.security_scan_on_start // false')"
SCAN_INTERVAL="$(cfg '.security_scan_interval_minutes // 360')"
BLOCK_EXT="$(cfg '.security_block_dangerous_extensions // true')"
DANGEROUS_EXT="$(cfg '.security_dangerous_extensions // "exe,dll,bat,cmd,com,scr,ps1,vbs,vbe,js,jse,wsf,wsh,msi,msp,hta,cpl,inf,reg,jar,iso,img,vhd,lnk"')"

[[ "$VIRUS_SCAN" == "null" ]] && VIRUS_SCAN=true
[[ "$QUARANTINE" == "null" ]] && QUARANTINE=true
[[ "$UPDATE_SIG" == "null" ]] && UPDATE_SIG=true
[[ "$SCAN_ON_START" == "null" ]] && SCAN_ON_START=false
[[ "$SCAN_INTERVAL" == "null" || -z "$SCAN_INTERVAL" ]] && SCAN_INTERVAL=360
[[ "$BLOCK_EXT" == "null" ]] && BLOCK_EXT=true
[[ "$DANGEROUS_EXT" == "null" || -z "$DANGEROUS_EXT" ]] && DANGEROUS_EXT="exe,dll,bat,cmd,com,scr,ps1,vbs,vbe,js,jse,wsf,wsh,msi,msp,hta,cpl,inf,reg,jar,iso,img,vhd,lnk"

QUAR_DIR=/data/quarantine
IMPORT_DIR=/data/import
SCAN_LOG=/data/security/last-scan.log
STATUS_FILE=/data/security/status.json
EVENTS_FILE=/data/security/events.jsonl
mkdir -p "$QUAR_DIR" "$IMPORT_DIR" /data/security /var/run/clamav
chown -R clamav:clamav /var/run/clamav 2>/dev/null || true

is_true() {
  case "${1,,}" in
    true|1|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

event() {
  local kind="$1" detail="$2"
  printf '{"ts":"%s","kind":"%s","detail":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$kind" "$(printf '%s' "$detail" | jq -Rs .)" \
    >> "$EVENTS_FILE" 2>/dev/null || true
}

write_status() {
  local enabled="$1" clamd="$2" last="$3" infected="$4" msg="$5"
  local scanning="${6:-false}"
  local current="${7:-}"
  local scanned="${8:-0}"
  local total_paths="${9:-0}"
  msg=${msg//\\/\\\\}
  msg=${msg//\"/\\\"}
  current=${current//\\/\\\\}
  current=${current//\"/\\\"}
  cat > "$STATUS_FILE" <<EOF
{
  "virus_scan_enabled": $enabled,
  "clamd_running": $clamd,
  "last_scan": "$last",
  "infected_moved": $infected,
  "quarantine_dir": "$QUAR_DIR",
  "message": "$msg",
  "scanning": $scanning,
  "current_path": "$current",
  "scanned_paths": $scanned,
  "total_paths": $total_paths
}
EOF
}

block_dangerous_files() {
  is_true "$BLOCK_EXT" || return 0
  log "Prüfe auf gefährliche Dateiendungen…"
  local count=0
  local IFS=','
  # shellcheck disable=SC2206
  local exts=( $DANGEROUS_EXT )
  local dir f ext base
  for dir in "$IMPORT_DIR" /data/mail-export /tmp/mail-import; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' f; do
      base="${f##*/}"
      ext="${base##*.}"
      ext="${ext,,}"
      for e in "${exts[@]}"; do
        e="${e// /}"
        e="${e,,}"
        [[ -z "$e" ]] && continue
        if [[ "$ext" == "$e" ]]; then
          log "Gefährliche Endung: $f → Quarantäne"
          mv -f "$f" "$QUAR_DIR/" 2>/dev/null || rm -f "$f"
          event "dangerous_extension" "$f"
          count=$((count + 1))
          break
        fi
      done
    done < <(find "$dir" -maxdepth 3 -type f -print0 2>/dev/null)
  done
  [[ "$count" -gt 0 ]] && log "$count Datei(en) mit gefährlicher Endung isoliert"
}

update_signatures() {
  is_true "$VIRUS_SCAN" || return 0
  is_true "$UPDATE_SIG" || { log "Signatur-Update übersprungen"; return 0; }
  log "Aktualisiere ClamAV-Signaturen (freshclam)…"
  if command -v freshclam >/dev/null 2>&1; then
    freshclam --quiet 2>&1 | tail -20 || log "WARNUNG: freshclam mit Fehlern"
    log "Signaturen aktualisiert"
  else
    log "freshclam nicht gefunden"
  fi
}

# Limit ClamAV resource use
for conf in /etc/clamav/clamd.conf /etc/clamav/clamd.conf.d/local.conf; do
  [[ -f "$conf" ]] || continue
  grep -q '^MaxThreads' "$conf" 2>/dev/null || echo 'MaxThreads 2' >> "$conf"
  grep -q '^MaxFileSize' "$conf" 2>/dev/null || echo 'MaxFileSize 25M' >> "$conf"
  grep -q '^MaxScanSize' "$conf" 2>/dev/null || echo 'MaxScanSize 50M' >> "$conf"
  grep -q '^StreamMaxLength' "$conf" 2>/dev/null || echo 'StreamMaxLength 25M' >> "$conf"
done

start_clamd() {
  is_true "$VIRUS_SCAN" || return 0
  if pgrep -x clamd >/dev/null 2>&1; then
    log "clamd läuft bereits"
    return 0
  fi
  log "Starte clamd…"
  if command -v clamd >/dev/null 2>&1; then
    clamd 2>/dev/null &
    local i
    for i in $(seq 1 30); do
      if pgrep -x clamd >/dev/null 2>&1; then
        log "clamd läuft"
        return 0
      fi
      sleep 1
    done
    log "WARNUNG: clamd startete nicht rechtzeitig"
  else
    log "clamd Binary nicht gefunden – Scan per clamscan CLI"
  fi
}

scan_path() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  is_true "$VIRUS_SCAN" || return 0
  local out infected=0
  log "Scanne: $path"
  write_status true "$(pgrep -x clamd >/dev/null && echo true || echo false)" "" 0 "Scanne $path" true "$path" "${SCANNED_N:-0}" "${SCAN_TOTAL:-0}"
  if pgrep -x clamd >/dev/null 2>&1 && command -v clamdscan >/dev/null 2>&1; then
    out=$(clamdscan --fdpass --move="$QUAR_DIR" "$path" 2>&1) || true
  elif command -v clamscan >/dev/null 2>&1; then
    out=$(clamscan -r --move="$QUAR_DIR" "$path" 2>&1) || true
  else
    log "Kein Scanner verfügbar"
    return 1
  fi

  echo "$out" >> "$SCAN_LOG"
  infected=$(echo "$out" | grep -c 'FOUND' || true)
  if [[ "${infected:-0}" -gt 0 ]]; then
    log "TREFFER: $infected infizierte Datei(en) unter $path"
    echo "$out" | grep 'FOUND' | while read -r line; do
      log "  $line"
      event "threat_found" "$line"
    done
  else
    log "Scan OK: $path"
  fi
  echo "$infected"
}

run_full_scan() {
  is_true "$VIRUS_SCAN" || return 0
  log "Starte Sicherheits-Scan…"
  event "scan_start" "full scan"
  : > "$SCAN_LOG"
  local total=0
  local n
  local paths=()
  local p
  for p in "$IMPORT_DIR" /data/mail-export /tmp/mail-import; do
    [[ -d "$p" ]] && paths+=("$p")
  done
  if [[ -d /data ]]; then
    while IFS= read -r -d '' f; do
      case "$f" in
        /data/pg/*|/data/keys/*|/data/security/*|/data/quarantine/*|/data/options.json) continue ;;
      esac
      paths+=("$f")
    done < <(find /data -maxdepth 2 -type f \( -name '*.eml' -o -name '*.mbox' -o -name '*.zip' -o -name '*.tar' -o -name '*.gz' \) -print0 2>/dev/null)
  fi
  SCAN_TOTAL=${#paths[@]}
  SCANNED_N=0
  write_status true "$(pgrep -x clamd >/dev/null && echo true || echo false)" "" 0 "Scan gestartet ($SCAN_TOTAL Ziele)" true "" 0 "$SCAN_TOTAL"
  for p in "${paths[@]}"; do
    SCANNED_N=$((SCANNED_N + 1))
    n=$(scan_path "$p" || echo 0)
    n=$(echo "$n" | tail -1)
    total=$((total + ${n:-0}))
  done

  if [[ -f /db_virus_scan.py ]]; then
    log "Starte Datenbank-Scan (inkrementell, Anhänge)…"
    event "db_scan_begin" "incremental attachments"
    set +e
    nice -n 15 ionice -c3 python3 /db_virus_scan.py 2>/dev/null || nice -n 15 python3 /db_virus_scan.py
    db_rc=$?
    set -e
    if [[ "$db_rc" -eq 2 ]]; then
      log "DB-Scan: Treffer gefunden"
    elif [[ "$db_rc" -ne 0 ]]; then
      log "WARNUNG: DB-Scan exit $db_rc"
    else
      log "DB-Scan ohne Treffer"
    fi
  else
    log "Hinweis: /db_virus_scan.py fehlt – nur Dateisystem gescannt"
  fi

  local now
  now=$(date -Iseconds)
  local db_hits=0
  if [[ -f "$STATUS_FILE" ]] && command -v jq >/dev/null 2>&1; then
    db_hits=$(jq -r '.infected_moved // 0' "$STATUS_FILE" 2>/dev/null || echo 0)
  fi
  local all_hits=$total
  if [[ -f /db_virus_scan.py ]]; then
    all_hits=$((total + ${db_hits:-0}))
  fi
  local msg
  if [[ "$all_hits" -gt 0 ]]; then
    msg="Scan fertig – $all_hits Treffer (FS: $total, DB: ${db_hits:-0})"
  else
    msg="Scan fertig – keine Treffer (Dateien: $SCAN_TOTAL, DB inkrementell)"
  fi
  write_status true "$(pgrep -x clamd >/dev/null && echo true || echo false)" "$now" "$all_hits" "$msg" false "" "$SCAN_TOTAL" "$SCAN_TOTAL"
  event "scan_end" "infected_moved=$all_hits fs=$total db=${db_hits:-0} scanned_fs=$SCAN_TOTAL"
  log "Scan abgeschlossen. Treffer gesamt: $all_hits (FS=$total DB=${db_hits:-0}) | FS-Ziele: $SCAN_TOTAL | Quarantäne: $QUAR_DIR"
}

background_loop() {
  is_true "$VIRUS_SCAN" || exit 0
  local mins="$SCAN_INTERVAL"
  if [[ "$mins" -le 0 ]] 2>/dev/null; then
    log "Periodischer Scan deaktiviert"
    exit 0
  fi
  log "Periodischer Scan alle $mins Minuten (niedrige Priorität)"
  while true; do
    sleep $((mins * 60))
    block_dangerous_files
    run_full_scan
  done
}

cmd="${1:-start}"
case "$cmd" in
  start)
    update_signatures
    start_clamd
    block_dangerous_files
    if is_true "$SCAN_ON_START"; then
      log "Starte Sicherheits-Scan im Hintergrund…"
      (
        run_full_scan
      ) &
    fi
    ;;
  scan)
    block_dangerous_files
    run_full_scan
    ;;
  update)
    update_signatures
    ;;
  loop)
    background_loop
    ;;
  status)
    cat "$STATUS_FILE" 2>/dev/null || echo '{"message":"no status yet"}'
    ;;
  *)
    echo "Usage: $0 {start|scan|update|loop|status}"
    exit 1
    ;;
esac

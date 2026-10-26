#!/usr/bin/env bash
set -euo pipefail

log() { echo "[mail-archiver] $*"; }

CFG="/data/options.json"

cfg() {
  if [ -f "$CFG" ]; then
    jq -r "$1" "$CFG" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

ADMIN_USER="$(cfg '.admin_username // "admin"')"
ADMIN_PASS="$(cfg '.admin_password // "changeme"')"
TIMEZONE="$(cfg '.timezone // "Europe/Berlin"')"
USE_EXT="$(cfg '.use_external_db // false')"
VIRUS_SCAN="$(cfg '.security_virus_scan // true')"

if [ -z "$ADMIN_USER" ] || [ "$ADMIN_USER" = "null" ]; then ADMIN_USER=admin; fi
if [ -z "$ADMIN_PASS" ] || [ "$ADMIN_PASS" = "null" ]; then ADMIN_PASS=changeme; fi
if [ -z "$TIMEZONE" ] || [ "$TIMEZONE" = "null" ]; then TIMEZONE=Europe/Berlin; fi

export TZ="$TIMEZONE"
ln -snf "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime 2>/dev/null || true
echo "$TIMEZONE" > /etc/timezone 2>/dev/null || true

start_embedded_postgres() {
  local pgdata="/data/pg"
  local PG_BIN
  PG_BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | head -1)"
  if [ -z "$PG_BIN" ]; then
    log "ERROR: PostgreSQL binaries nicht gefunden"
    exit 1
  fi

  if [ ! -f "${pgdata}/PG_VERSION" ]; then
    log "Initialisiere PostgreSQL in $pgdata"
    mkdir -p "$pgdata"
    chown postgres:postgres "$pgdata"
    chmod 700 "$pgdata"
    su -s /bin/bash postgres -c "${PG_BIN}/initdb -D ${pgdata} --username=postgres --auth-local=trust --auth-host=trust"
    {
      echo "listen_addresses = '127.0.0.1'"
      echo "unix_socket_directories = '/tmp'"
      echo "logging_collector = off"
      echo "log_destination = 'stderr'"
    } >> "${pgdata}/postgresql.conf"
  fi

  chown -R postgres:postgres "$pgdata"
  chmod 700 "$pgdata"

  local pglog="${pgdata}/postgres.log"
  touch "$pglog" 2>/dev/null || true
  chown postgres:postgres "$pglog" 2>/dev/null || true

  if ! su -s /bin/bash postgres -c "${PG_BIN}/pg_ctl -D ${pgdata} status" >/dev/null 2>&1; then
    log "Starte PostgreSQL"
    su -s /bin/bash postgres -c "${PG_BIN}/pg_ctl -D ${pgdata} -m fast stop" >/dev/null 2>&1 || true
    sleep 1
    su -s /bin/bash postgres -c "${PG_BIN}/pg_ctl -D ${pgdata} -l ${pglog} -w -o '-k /tmp -c listen_addresses=127.0.0.1' start"
  fi

  local i
  for i in $(seq 1 30); do
    if su -s /bin/bash postgres -c "${PG_BIN}/pg_isready -h 127.0.0.1" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if ! su -s /bin/bash postgres -c "${PG_BIN}/pg_isready -h 127.0.0.1" >/dev/null 2>&1; then
    log "ERROR: PostgreSQL startete nicht"
    tail -50 "$pglog" 2>/dev/null || true
    exit 1
  fi

  su -s /bin/bash postgres -c "${PG_BIN}/psql -h 127.0.0.1 -v ON_ERROR_STOP=1 -d postgres" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mailuser') THEN
    CREATE ROLE mailuser LOGIN SUPERUSER PASSWORD 'mailuser';
  END IF;
END
$$;
SELECT 'CREATE DATABASE "MailArchiver" OWNER mailuser'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'MailArchiver')\gexec
SQL

  DB_HOST=127.0.0.1
  DB_PORT=5432
  DB_NAME=MailArchiver
  DB_USER=mailuser
  DB_PASS=mailuser
}

if [ "$USE_EXT" = "true" ]; then
  DB_HOST="$(cfg '.db_host // ""')"
  DB_PORT="$(cfg '.db_port // "5432"')"
  DB_NAME="$(cfg '.db_name // "MailArchiver"')"
  DB_USER="$(cfg '.db_user // "mailuser"')"
  DB_PASS="$(cfg '.db_password // ""')"
  if [ "$DB_HOST" = "null" ] || [ -z "$DB_HOST" ] || [ "$DB_HOST" = "postgres" ]; then
    start_embedded_postgres
  else
    log "Externe Datenbank ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
  fi
else
  start_embedded_postgres
fi

export ConnectionStrings__DefaultConnection="Host=${DB_HOST};Port=${DB_PORT};Database=${DB_NAME};Username=${DB_USER};Password=${DB_PASS}"
export Authentication__Username="${ADMIN_USER}"
export Authentication__Password="${ADMIN_PASS}"
export Authentication__SessionTimeoutMinutes=120
export Authentication__CookieName=MailArchiverAuth
export Authentication__CookieSameSite=Lax
export Dashboard__RefreshIntervalMinutes=15
export Dashboard__CacheSeconds=60
export TimeZone__DisplayTimeZoneId="${TIMEZONE}"
export AllowedHosts="*"
export ASPNETCORE_URLS="http://127.0.0.1:5001"
export ASPNETCORE_ENVIRONMENT=Production
export ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
# Persist ASP.NET Data Protection keys across restarts (session cookies)
export DOTNET_DataProtection__KeyDirectory=/data/keys
export DataProtection__KeyPath=/data/keys
mkdir -p /data/keys
chmod 700 /data/keys 2>/dev/null || true
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=0
export DB_SCAN_BODIES="${DB_SCAN_BODIES:-false}"
export DB_SCAN_MAX_PER_RUN="${DB_SCAN_MAX_PER_RUN:-800}"

mkdir -p /data/keys /data/import /data/quarantine /data/security /app/imports
log "Bereinige Temp-Ordner…"
rm -rf /data/import/.upload_tmp 2>/dev/null || true
mkdir -p /data/import/.upload_tmp
rm -rf /var/lib/nginx/body/* 2>/dev/null || true
rm -rf /tmp/nginx_client_body* 2>/dev/null || true
rm -rf /app/uploads/eml/.tmp 2>/dev/null || true
find /app/uploads/eml -type f -name '*.part' -delete 2>/dev/null || true
find /data/import -maxdepth 1 -type f \( -name '*.part' -o -name '.*.json' \) -delete 2>/dev/null || true
log "Temp-Bereinigung fertig"
ln -sfn /data/import /app/imports 2>/dev/null || true
ln -sfn /data/import /app/uploads/eml 2>/dev/null || true

# Security: NIE den Boot blockieren
if [ -f /security.sh ]; then
  log "Starte Sicherheitsmodul im Hintergrund…"
  (
    bash /security.sh start || log "WARN: security.sh start fehlgeschlagen"
    bash /security.sh loop || true
  ) &
fi

if [ -f /security_ui.py ]; then
  log "Starte Security-Dashboard auf :5002 (/security/)"
  python3 /security_ui.py >> /data/security/security_ui.log 2>&1 &
fi

if [ ! -f /nginx.conf.template ]; then
  log "ERROR: /nginx.conf.template fehlt"
  exit 1
fi
cp /nginx.conf.template /tmp/nginx.conf
if ! nginx -t -c /tmp/nginx.conf; then
  log "ERROR: nginx Konfiguration ungültig"
  cat /tmp/nginx.conf
  exit 1
fi

log "App intern auf 127.0.0.1:5001, Ingress auf Port 5000"
log "Login: ${ADMIN_USER}"
log "Virenscan: ${VIRUS_SCAN} | Dashboard: /security/ | Quarantäne: /data/quarantine | Import: /data/import"
log "Direkt: http://<ha-ip>:5000  und  http://<ha-ip>:5000/security/"

nginx -c /tmp/nginx.conf -g 'daemon off;' &

cd /app
exec dotnet MailArchiver.dll

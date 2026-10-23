#!/bin/bash
set -euo pipefail

log() { echo "[mail-archiver] $*"; }

OPTIONS=/data/options.json
if [ ! -f "$OPTIONS" ]; then
  echo '{}' > /tmp/options.json
  OPTIONS=/tmp/options.json
fi

cfg() { jq -r "$1" "$OPTIONS"; }

ADMIN_USER="$(cfg '.admin_username // "admin"')"
ADMIN_PASS="$(cfg '.admin_password // "changeme"')"
TIMEZONE="$(cfg '.timezone // "Europe/Berlin"')"
USE_EXT="$(cfg '.use_external_db // false')"

[ "$ADMIN_USER" = "null" ] || [ -z "$ADMIN_USER" ] && ADMIN_USER=admin
[ "$ADMIN_PASS" = "null" ] || [ -z "$ADMIN_PASS" ] && ADMIN_PASS=changeme
[ "$TIMEZONE" = "null" ] || [ -z "$TIMEZONE" ] && TIMEZONE=Europe/Berlin

if [ -f "/usr/share/zoneinfo/${TIMEZONE}" ]; then
  ln -sfn "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime
  echo "$TIMEZONE" > /etc/timezone
fi
export TZ="$TIMEZONE"

PG_BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"
if [ -z "$PG_BIN" ]; then
  log "ERROR: PostgreSQL binaries not found"
  exit 1
fi

start_embedded_postgres() {
  local pgdata=/data/pg
  mkdir -p /data
  chown postgres:postgres /data 2>/dev/null || true

  if [ ! -s "${pgdata}/PG_VERSION" ]; then
    log "Initialisiere lokale PostgreSQL-Datenbank in ${pgdata}"
    rm -rf "$pgdata"
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
export TimeZone__DisplayTimeZoneId="${TIMEZONE}"
export AllowedHosts="*"
export ASPNETCORE_URLS="http://127.0.0.1:5001"
export ASPNETCORE_ENVIRONMENT=Production
# Avoid broken HTTPS redirects behind HA ingress
export ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=0

mkdir -p /data/keys
if [ -e /app/DataProtection-Keys ] && [ ! -L /app/DataProtection-Keys ]; then
  rm -rf /app/DataProtection-Keys
fi
ln -sfn /data/keys /app/DataProtection-Keys

cp /nginx.conf.template /tmp/nginx.conf
if ! nginx -t -c /tmp/nginx.conf; then
  log "ERROR: nginx Konfiguration ungültig"
  cat /tmp/nginx.conf
  exit 1
fi

log "App intern auf 127.0.0.1:5001, Ingress auf Port 5000"
log "Login: ${ADMIN_USER}"
log "Direkt (ohne Ingress): http://<ha-ip>:5000"

nginx -c /tmp/nginx.conf -g 'daemon off;' &

cd /app
exec dotnet MailArchiver.dll

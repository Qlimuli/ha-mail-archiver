#!/usr/bin/with-contenv bashio
# ==============================================================================
# Home Assistant Add-on: Mail Archiver
# ==============================================================================

set -e

ADMIN_USER=$(bashio::config 'admin_username')
ADMIN_PASS=$(bashio::config 'admin_password')
TIMEZONE=$(bashio::config 'timezone')
DB_HOST=$(bashio::config 'db_host')
DB_PORT=$(bashio::config 'db_port')
DB_NAME=$(bashio::config 'db_name')
DB_USER=$(bashio::config 'db_user')
DB_PASS=$(bashio::config 'db_password')

if [ -z "${DB_PASS}" ]; then
    bashio::log.fatal "Datenbank-Passwort ist nicht gesetzt!"
    bashio::exit.nok
fi

bashio::log.info "Starte Mail Archiver..."
bashio::log.info "Datenbank: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
bashio::log.info "Zeitzone: ${TIMEZONE}"

# Environment Variables für Mail-Archiver
export ConnectionStrings__DefaultConnection="Host=${DB_HOST};Port=${DB_PORT};Database=${DB_NAME};Username=${DB_USER};Password=${DB_PASS}"
export Authentication__Username="${ADMIN_USER}"
export Authentication__Password="${ADMIN_PASS}"
export Authentication__SessionTimeoutMinutes=120
export Authentication__CookieName=MailArchiverAuth
export Authentication__CookieSameSite=Lax
export TimeZone__DisplayTimeZoneId="${TIMEZONE}"

# Data Protection Keys persistent speichern
mkdir -p /data/DataProtection-Keys
export ASPNETCORE_DATA_PROTECTION_KEYS_PATH=/data/DataProtection-Keys

# ASP.NET Core auf alle Interfaces und Port 5000 binden (für Ingress)
export ASPNETCORE_URLS="http://0.0.0.0:5000"

bashio::log.info "Starte Anwendung..."

# Starte die originale MailArchiver Anwendung
exec /app/MailArchiver

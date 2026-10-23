# Mail Archiver

Lokales E-Mail-Archiv in der Home-Assistant-Sidebar.

Die Mails liegen in einer PostgreSQL-Datenbank **im Add-on** (`/data`). Ein extra PostgreSQL-Add-on ist nicht nötig.

## Warum frühere Versionen nicht liefen

- **1.0.x**: Upstream-Image startet mit `Host=postgres`. In HA gibt es diesen Host nicht → Verbindungsfehler.
- **1.1.0–1.1.3**: Ingress-Pfade wurden mit nginx-Lua umgeschrieben. In manchen Images fehlt `ngx_http_lua_module` → „lua-Modul fehlt“. Zusätzlich konnte der Postgres-Log unter `/data/pg.log` Permission denied verursachen.
- **1.1.4**: Nutzt nur noch das eingebaute nginx-`sub_filter`-Modul und schreibt Postgres-Logs in `/data/pg/postgres.log`.

## Einrichtung

1. Add-on **neu bauen** (Repository aktualisieren, Version 1.1.4, nicht nur neu starten).
2. In der Konfiguration `admin_password` ändern. `use_external_db` auf **false** lassen.
3. Starten. In der Sidebar **Mail** öffnen.
4. Anmelden mit `admin_username` / `admin_password`.
5. Unter E-Mail-Konten Gmail oder GMX eintragen.

### Gmail

- IMAP in Gmail aktivieren
- 2FA an, dann ein App-Passwort erzeugen
- Server `imap.gmail.com`, Port `993`, SSL

### GMX

- In GMX unter Einstellungen POP3/IMAP einschalten
- Server `imap.gmx.net` (oder `imap.gmx.com`), Port `993`, SSL
- normales GMX-Passwort

## Externe Datenbank

Nur wenn du schon ein PostgreSQL-Add-on hast:

- `use_external_db`: true
- `db_host`: Hostname des Add-ons. **Nicht** `postgres`.

## Backup

Home-Assistant-Backup des Add-ons sichert `/data` inklusive der Mail-Datenbank.

# Home Assistant Add-on: Mail Archiver

Lokales E-Mail-Archiv (Gmail, GMX, beliebiges IMAP) in der Sidebar.

PostgreSQL läuft im Add-on. `use_external_db` auf **false** lassen. `db_host` leer lassen.

Repository-URL: `https://github.com/Qlimuli/ha-mail-archiver`

Aktuelle Version: **1.1.6**

## Nutzung

1. Add-on bauen & starten
2. Sidebar **Mail** öffnen **oder** unter dem Add-on „In Browser öffnen“ (Port 5000)
3. Login mit `admin_username` / `admin_password`

## Changelog

### 1.1.6
- Ingress: Location-Redirects und Cookie-Path korrekt umschreiben
- Fallback, falls der volle Ingress-Pfad an nginx kommt
- `<base href>` für korrekte Asset-Pfade → kein Whitescreen mehr

### 1.1.5
- nginx `sub_filter`-Quoting behoben

### 1.1.4
- Standard-`sub_filter` statt Lua, Postgres-Log-Rechte

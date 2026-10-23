# Home Assistant Add-on: Mail Archiver

Lokales E-Mail-Archiv (Gmail, GMX, beliebiges IMAP) in der Sidebar.

PostgreSQL läuft im Add-on. `use_external_db` auf false lassen. `db_host` leer lassen.

Repository-URL: `https://github.com/Qlimuli/ha-mail-archiver`

Aktuelle Version: **1.1.5**

## Changelog

### 1.1.5
- nginx `sub_filter`-Anführungszeichen korrigiert (Fehler: unexpected "h")
- doppelter MIME-Type-Warnung behoben

### 1.1.4
- Standard-`sub_filter` statt Lua
- PostgreSQL-Log unter `/data/pg/postgres.log`

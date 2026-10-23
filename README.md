# Home Assistant Add-on: Mail Archiver

Lokales E-Mail-Archiv (Gmail, GMX, beliebiges IMAP) in der Sidebar.

PostgreSQL läuft im Add-on. `use_external_db` auf false lassen.

Repository-URL: `https://github.com/Qlimuli/ha-mail-archiver`

Aktuelle Version: **1.1.4**

## Changelog 1.1.4

- Nginx nutzt Standard-`sub_filter` statt Lua (kein „lua-Modul fehlt“ mehr)
- PostgreSQL-Log und Berechtigungen unter `/data/pg` korrigiert
- Stabilerer Start (kein `/data/pg.log` Permission denied)

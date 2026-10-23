# Home Assistant Add-on: Mail Archiver

Lokales E-Mail-Archiv (Gmail, GMX, beliebiges IMAP) mit Oberfläche in der Sidebar.

Basiert auf [s1t5/mail-archiver](https://github.com/s1t5/mail-archiver). PostgreSQL läuft im Add-on, es ist kein zweites Add-on nötig.

## Installation

1. **Einstellungen → Add-ons → Add-on Store → ⋮ → Repositories**
2. URL dieses Repositories eintragen: `https://github.com/Qlimuli/ha-mail-archiver`
3. **Mail Archiver** installieren, Passwort setzen, starten
4. Sidebar-Eintrag **Mail**

`use_external_db` auf false lassen. Der Hostname `postgres` existiert in Home Assistant nicht.

## Version 1.1.0

- Startskript ersetzt den Upstream-Entrypoint (sonst blieb `Host=postgres` aktiv)
- Eingebettete PostgreSQL-Datenbank unter `/data/pg`
- Nginx schreibt Ingress-Pfade um, damit die Oberfläche keine 404 auf `/` zeigt

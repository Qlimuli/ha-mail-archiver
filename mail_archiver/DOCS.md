# Mail Archiver

Lokales E-Mail-Archiv in der Home-Assistant-Sidebar.

Die Mails liegen in einer PostgreSQL-Datenbank **im Add-on** (`/data`). Ein extra PostgreSQL-Add-on ist nicht nötig.

## Warum Version 1.0.0 nicht lief

Das Upstream-Image startet fest mit `ENTRYPOINT dotnet MailArchiver.dll` und der Verbindungszeichenfolge `Host=postgres`.
Ein `CMD`-Skript wird dadurch ignoriert. In Home Assistant gibt es keinen Host `postgres`, deshalb:

`Name or service not known` auf `tcp://postgres:5432`

Die 404 in der Oberfläche kommt dazu, weil Mail-Archiver Adressen wie `/Account/Login` erzeugt. Der Ingress-Proxy von Home Assistant reicht nur Pfade unter `/api/hassio_ingress/...` durch. Version 1.1.0 setzt die Datenbank lokal und schreibt diese Pfade um.

## Einrichtung

1. Add-on **neu bauen** (Repository aktualisieren, Version 1.1.0, nicht nur neu starten).
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

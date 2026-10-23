# Mail Archiver

Lokales E-Mail-Archiv für Home Assistant mit voller Weboberfläche und Ingress-Unterstützung.

## Über das Add-on

Dieses Add-on packt das Projekt [Mail-Archiver](https://github.com/s1t5/mail-archiver) als Home Assistant Add-on.

Die Mails werden **dauerhaft lokal** in einer PostgreSQL-Datenbank gespeichert. Damit hast du ein echtes Backup deiner E-Mails auf dem Home Assistant.

## Voraussetzungen

- Home Assistant OS / Supervised
- Offizielles **PostgreSQL** Add-on muss installiert und gestartet sein

## PostgreSQL vorbereiten

Öffne den PostgreSQL-Client (im PostgreSQL Add-on) und führe aus:

```sql
CREATE DATABASE "MailArchiver";
CREATE USER mailuser WITH ENCRYPTED PASSWORD 'dein_sicheres_passwort';
GRANT ALL PRIVILEGES ON DATABASE "MailArchiver" TO mailuser;
\c MailArchiver
GRANT ALL ON SCHEMA public TO mailuser;
ALTER DATABASE "MailArchiver" OWNER TO mailuser;
```

Trage danach die gleichen Werte in der Add-on-Konfiguration ein.

## Konfiguration

| Option | Beschreibung | Standard |
|--------|--------------|----------|
| admin_username | Benutzername für die Weboberfläche | admin |
| admin_password | Passwort für die Weboberfläche | changeme |
| timezone | IANA Zeitzone | Europe/Berlin |
| db_host | Hostname der PostgreSQL-Instanz | core-postgresql |
| db_port | Port | 5432 |
| db_name | Datenbankname | MailArchiver |
| db_user | Datenbankbenutzer | mailuser |
| db_password | Datenbankpasswort | (leer) |

## Erste Nutzung

1. Add-on starten
2. In der Sidebar auf **Mail Archiver** klicken
3. Mit den konfigurierten Zugangsdaten anmelden
4. Unter **Email Accounts** neue Konten hinzufügen

### Gmail

- 2-Faktor-Authentifizierung muss aktiviert sein
- App-Passwort erstellen (Google-Konto → Sicherheit → App-Passwörter)
- Server: `imap.gmail.com`, Port `993`, SSL

### GMX

- In den GMX-Einstellungen POP3/IMAP aktivieren
- Server: `imap.gmx.net` (oder `imap.gmx.com`), Port `993`, SSL
- Normales Passwort verwenden

## Backup

Die Mails liegen in der PostgreSQL-Datenbank.  
Sichere regelmäßig das PostgreSQL-Add-on über die Home Assistant Backup-Funktion.

## Support

- Upstream: https://github.com/s1t5/mail-archiver
- Add-on Issues: https://github.com/YOUR_USERNAME/ha-mail-archiver/issues

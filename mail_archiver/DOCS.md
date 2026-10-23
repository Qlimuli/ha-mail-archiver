# Mail Archiver

Lokales E-Mail-Archiv in der Home-Assistant-Sidebar, optional mit **ClamAV-Virenscan** und Quarantäne.

## Sicherheit (ab 1.2.0)

| Option | Standard | Bedeutung |
|--------|----------|-----------|
| `security_virus_scan` | **true** | ClamAV aktiv (Signaturen + Scan) |
| `security_quarantine` | **true** | Infizierte Dateien nach `/data/quarantine` verschieben |
| `security_update_signatures_on_start` | true | Beim Start `freshclam` (Signatur-Update) |
| `security_scan_on_start` | true | Scan von Import-/Export-Ordnern beim Start |
| `security_scan_interval_minutes` | 60 | Periodischer Rescan (0 = aus) |
| `security_block_dangerous_extensions` | true | `.exe`, `.js`, `.bat`, … sofort in Quarantäne |
| `security_dangerous_extensions` | (Liste) | Kommagetrennte Endungen ohne Punkt |

### Was wird gescannt?

- `/data/import` – leg hier EML/ZIP/MBox **vor dem Import** ab und warte auf den Scan
- `/data/mail-export` und ähnliche Export-Ordner
- lose `*.eml` / `*.mbox` / `*.zip` unter `/data`

Infizierte Dateien landen in **`/data/quarantine`** (wenn Quarantäne an ist) und werden **nicht** im Archiv belassen, soweit sie als Datei auf der Festplatte liegen.

### Wichtiger Hinweis

Anhänge, die die App **bereits in der PostgreSQL-Datenbank** gespeichert hat (IMAP-Sync / Web-Upload direkt in die App), liegen als Binärdaten in der DB. ClamAV im Add-on scannt diese Blobs **nicht einzeln aus der DB**.  

**Empfohlener sicherer Ablauf für Mailstation-Import:**

1. Maildir → EML (Skript) auf dem PC  
2. Windows Defender / ClamAV lokal über den Export  
3. Saubere Dateien nach `/data/import` (oder ZIP über die UI)  
4. Add-on scannt `/data/import` beim Start und periodisch  
5. Erst dann in der UI importieren  

So liegen keine bekannten Schadfiles als lose Dateien im Add-on.

### Status

Nach dem Start: `/data/security/status.json` und Logzeilen `[mail-archiver:security]`.

## Datenbank

`use_external_db: false`, `db_host` leer → PostgreSQL im Add-on unter `/data/pg`.

## Login

`admin_username` / `admin_password` in den Add-on-Optionen.

## GUI: Sicherheit (nur Admin)

Unter **Sicherheit** in der Navbar (nur sichtbar wenn „Benutzer“ in der Navbar ist):

- **Übersicht** – Status, Ereignisse, Quarantäne, Import-Ordner, Scan-Log
- **Konfiguration** – aktuelle `security_*`-Optionen + manuelle Aktionen (Scan, Signaturen)

Pfad im Ingress: `/security/`

# Home Assistant Add-on: Mail Archiver

Lokales E-Mail-Archiv (Gmail, GMX, IMAP) in der Sidebar – mit optionalem **ClamAV-Virenscan** und Quarantäne.

Repository: `https://github.com/Qlimuli/ha-mail-archiver`  
Version: **1.2.0**

## Sicherheit (Standard: an)

In den Add-on-Optionen:

- **security_virus_scan** – ClamAV an/aus  
- **security_quarantine** – Treffer nach `/data/quarantine`  
- **security_block_dangerous_extensions** – `.exe`, `.js`, `.bat`, … blockieren  
- **security_scan_interval_minutes** – periodischer Scan (0 = aus)

Import-Dateien möglichst nach `/data/import` legen; der Scanner prüft sie vor/neben dem Betrieb.

Details: `mail_archiver/DOCS.md`

## Quick-Start

1. Add-on bauen (1.2.0), starten  
2. Starkes `admin_password` setzen  
3. `use_external_db: false`  
4. Sidebar **Mail** oder Port 5000  

## Changelog 1.2.0

- ClamAV + freshclam im Image  
- Konfigurierbare Security-Optionen  
- Quarantäne-Ordner `/data/quarantine`  
- Blocklist gefährlicher Dateiendungen  
- Scan beim Start + periodisch  

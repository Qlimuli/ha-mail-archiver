# Home Assistant Add-on: Mail Archiver

Version **1.2.1** – Archiv + ClamAV + **Security-Dashboard**.

## Virenschutz-GUI

Nach dem Start öffnen:

- Direkt: `http://<ha-ip>:5000/security/`
- Per Ingress: `…/security/` an die Ingress-URL anhängen

Dort siehst du:

- Status (an/aus, clamd, letzter Scan, Treffer)
- Ereignisse (Erkennungen, Blocklist, Scans)
- Quarantäne-Inhalt
- Import-Ordner
- Scan-Log
- Button **Scan jetzt starten**

## Optionen

`security_virus_scan`, `security_quarantine`, Intervall, gefährliche Endungen – in den Add-on-Einstellungen.

## Build

Add-on **neu bauen** (1.2.1), nicht nur neu starten.

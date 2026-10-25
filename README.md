# Home Assistant Add-on: Mail Archiver

Version **1.3.17**

## 1.3.17 – Vollständiger Datenbank-Virenscan

Der Security-Scan prüft nicht nur Import-Dateien, sondern:

1. Dateisystem (`/data/import` u. a.)
2. **Alle Anhänge** in der DB (`AttachmentContents` + Legacy)
3. **Alle E-Mail-Bodies** (Text + HTML)

Treffer werden nach `/data/quarantine` kopiert und im Security-Dashboard angezeigt.

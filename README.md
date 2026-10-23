# Home Assistant Add-on: Mail Archiver

Version **1.2.7**

## Sicherheit in der Top-Leiste (nur Admin)

**Sicherheit** erscheint nach **Protokoll**, nur wenn **Benutzer** sichtbar ist (Admin).

Add-on auf **1.2.7 neu bauen**, Seite hart neu laden (Strg+F5).

## 1.2.7 – Upload-Fortschrittsbalken

- Beim ZIP/EML-Upload erscheint direkt am Button ein **Fortschrittsbalken** (Prozent + gesendete Größe)
- Nach 100 % Upload: Anzeige „Server verarbeitet…“
- Nutzt XHR mit `upload.onprogress` (nicht erst nach Server-Antwort)

## 1.2.6 – Sicherheit in der Top-Leiste

- Robuster Navbar-Inject nach Protokoll

## 1.2.5 – Sicherheit (Admin)

- GUI Übersicht + Konfiguration, Scan / Signaturen

## 1.2.4 – EML/ZIP-Upload Fix

- Datei-wählen-Button, große Uploads stabiler

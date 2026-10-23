# Home Assistant Add-on: Mail Archiver

Version **1.2.5**

## Virenschutz (nur Admin)

In der oberen Leiste erscheint **Sicherheit** (Schild) **nur wenn** in der Navbar **Benutzer** sichtbar ist (Admin).

Eingefügt direkt nach **Protokoll**.

Add-on auf **1.2.5 neu bauen**, Seite hart neu laden (Strg+F5).

## 1.2.5 – Sicherheit (Admin)

- Eigene GUI-Sektion **Sicherheit** (nur Admin, Navbar-Link)
- Tabs: **Übersicht** (Status, Ereignisse, Quarantäne, Import, Log) und **Konfiguration**
- Anzeige aller `security_*` Add-on-Optionen
- Aktionen: Scan starten, ClamAV-Signaturen aktualisieren

Add-on neu bauen, Seite hart neu laden (Strg+F5).

## 1.2.4 – EML/ZIP-Upload Fix

- Sichtbarer **Datei wählen**-Button auf der EML-Import-Seite (HA-Ingress)
- Submit-Button wird zuverlässig aktiviert
- nginx: `proxy_request_buffering off` + längere Timeouts für große Uploads
- LocalImport-Pfade `/data/import` und `/app/imports` verknüpft
- Upload-Limits (bis 10 GB) per Environment gesetzt

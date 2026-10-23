# Home Assistant Add-on: Mail Archiver

Version **1.2.4**

## Virenschutz (nur Admin)

In der oberen Leiste erscheint **Virenschutz** (Schild) **nur wenn** in der Navbar **Benutzer** sichtbar ist (Admin).

Eingefügt direkt nach **Protokoll**.

Add-on auf **1.2.4 neu bauen**, Seite hart neu laden (Strg+F5).

## 1.2.4 – EML/ZIP-Upload Fix

- Sichtbarer **Datei wählen**-Button auf der EML-Import-Seite (HA-Ingress)
- Submit-Button wird zuverlässig aktiviert
- nginx: `proxy_request_buffering off` + längere Timeouts für große Uploads
- LocalImport-Pfade `/data/import` und `/app/imports` verknüpft
- Upload-Limits (bis 10 GB) per Environment gesetzt

Add-on neu bauen, Seite hart neu laden (Strg+F5).

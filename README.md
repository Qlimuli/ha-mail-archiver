# Home Assistant Add-on: Mail Archiver

Version **1.2.8**

## Sicherheit in der Top-Leiste (nur Admin)

**Sicherheit** erscheint nach **Protokoll**, nur wenn **Benutzer** sichtbar ist (Admin).

Add-on auf **1.2.8 neu bauen**, Seite hart neu laden (Strg+F5).

## 1.2.8 – nginx-Fix (Inject-Skript)

- Langes Inline-JS aus der nginx-`map` entfernt (Fehler: *too long parameter*)
- Logik in `/ha-ui-inject.js` ausgelagert; nur noch kurzes `<script src="…">`
- Upload-Fortschrittsbalken und Sicherheit-Navbar bleiben erhalten

## 1.2.7 – Upload-Fortschrittsbalken

- XHR-Progress beim ZIP/EML-Upload

## 1.2.6 – Sicherheit in der Top-Leiste

- Robuster Navbar-Inject nach Protokoll

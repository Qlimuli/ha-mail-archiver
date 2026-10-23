# Home Assistant Add-on: Mail Archiver

Version **1.2.6**

## Sicherheit in der Top-Leiste (nur Admin)

In der oberen Leiste erscheint **Sicherheit** (Schild) **nur wenn** in der Navbar **Benutzer** sichtbar ist (Admin).

Eingefügt direkt nach **Protokoll**.

Add-on auf **1.2.6 neu bauen**, Seite hart neu laden (Strg+F5).

## 1.2.6 – Sicherheit in der Top-Leiste

- Robuster Navbar-Inject: **Sicherheit** erscheint nach **Protokoll** (nur Admin)
- Mehrere Versuche + MutationObserver, falls die Leiste verzögert geladen wird
- Passendes `nav-link`-Styling wie die übrigen Menüpunkte

## 1.2.5 – Sicherheit (Admin)

- GUI-Sektion **Sicherheit** mit Tabs Übersicht + Konfiguration
- Scan / Signaturen aktualisieren

## 1.2.4 – EML/ZIP-Upload Fix

- Sichtbarer Datei-wählen-Button, große Uploads stabiler

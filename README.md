# Home Assistant Add-on: Mail Archiver

Version **1.3.0**

## 1.3.0 – Import-Job nach Chunk-Upload

- Nach großem ZIP-Upload wird automatisch `dotnet … --import-eml` gestartet
- Es erscheint wie bei kleinen Dateien ein Eintrag unter **EML-Import-Jobs**
- Weiterleitung zur Jobs-Seite

Add-on **1.3.0** neu bauen, Strg+F5.

## 1.2.9 – Chunk-Upload

- Große Dateien in 4-MB-Teilen (HA-Ingress)

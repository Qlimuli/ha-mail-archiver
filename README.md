# Home Assistant Add-on: Mail Archiver

Version **1.2.9**

## 1.2.9 – Chunk-Upload (große ZIP)

- Uploads **≥ 8 MB** laufen in **4-MB-Teilen** über `/security/api/upload-chunk`
- Behebt Hänger bei ~25 % / ~200 MB durch den Home-Assistant-Ingress
- Fortschrittsbalken + Abbrechen
- Fertige Datei liegt in `/data/import/` (danach Local Import)

Add-on **1.2.9** neu bauen, Strg+F5.

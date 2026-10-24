# Home Assistant Add-on: Mail Archiver

Version **1.3.2**

## 1.3.2 – Import/Temp-Bereinigung

- Nach erfolgreichem Import: Quelldatei unter `/data/import` wird gelöscht
- Beim Add-on-Start: `.upload_tmp`, nginx-Body-Temps und `.part`-Reste werden bereinigt
- API `POST /security/api/cleanup-import` (optional `{"all":true}` für alle Dateien in `/data/import`)

Add-on **1.3.2** neu bauen.

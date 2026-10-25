# Home Assistant Add-on: Mail Archiver

Version **1.3.27**

## 1.3.27 – Security-Dashboard 502 behoben

* Dockerfile kopiert jetzt alle `mail_rules_part*.b64` ins Image
* Security-UI startet auch, wenn mail_rules fehlt (nur Regeln deaktiviert)
* Loader sucht Parts in `/` und neben `mail_rules.py`

**Add-on 1.3.27 neu bauen** – danach `/security/` wieder erreichbar.

## 1.3.26 – Remote-Ordner vollständiger erkennen

* IMAP-LIST robuster, bis 200 Ordner, GMX alle Mailboxen
* Event-Log `remote_folders`

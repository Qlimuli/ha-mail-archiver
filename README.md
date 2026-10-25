# Home Assistant Add-on: Mail Archiver

Version **1.3.28**

## 1.3.28 – CPU/RAM optimiert

* DB-Virenscan **inkrementell** (nur neue Anhänge), max. 800 pro Lauf
* E-Mail-Bodies standardmäßig **nicht** gescannt
* ClamAV: MaxThreads=2, Größenlimits, `nice`/`ionice`
* Scan-Intervall Default **360 Min**, Scan-on-Start **aus**
* Security-UI Polling 30s, schlankeres Status-JSON
* Dashboard-Stats alle 15 Min

## 1.3.27 – Security 502

`mail_rules_part*.b64` im Image.

## 1.3.26 – Remote-Ordner

IMAP-LIST robuster.

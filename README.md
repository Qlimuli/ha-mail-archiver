# Home Assistant Add-on: Mail Archiver

Version **1.3.18**

## 1.3.18 – Remote-Löschen zuverlässiger

Beim **Jetzt löschen** der Mailregeln:

- Zuerst **IMAP-Löschen** auf dem Server (alle Ordner, Message-ID)
- Danach lokal im Archiv

Remote ist standardmäßig aktiv. Ergebnis enthält `remote.remote_deleted` und `folders_tried`.

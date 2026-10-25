# Home Assistant Add-on: Mail Archiver

Version **1.3.26**

## 1.3.26 – Remote-Ordner vollständiger erkennen

* IMAP-LIST robuster (quoted names, Hierarchie, kein „/“-Phantom)
* Bis zu **200** Ordner pro Konto (statt 40)
* GMX & Co.: alle auswählbaren Mailboxen, nicht nur INBOX + wenige
* Mehr LIST/LSUB-Varianten (`\"\" \"*\"`, `%`, LSUB)
* Event-Log: `remote_folders` mit discovered/scan/sample

Add-on **1.3.26** neu bauen, dann erneut Vorschau / Löschen.

## 1.3.20 – Übersicht nach „Jetzt löschen“

Nach Vorschau / Löschen siehst du:

- Lokal gelöscht / Treffer
- Remote-Kandidaten
- Remote gelöscht
- Remote nicht gefunden
- Pro Konto: gelöscht, Fehler, durchsuchte Ordner

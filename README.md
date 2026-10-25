# Home Assistant Add-on: Mail Archiver

Version **1.3.26**

## ⚠️ 1.3.26 – mail_rules.py wiederherstellen

Bei einem Push wurde `mail_archiver/rootfs/mail_rules.py` kurz geleert. Bitte lokal wiederherstellen:

```bash
git clone https://github.com/Qlimuli/ha-mail-archiver.git
cd ha-mail-archiver
git checkout 2bc26221efe9403f4163d6351b7834d3314b4835 -- mail_archiver/rootfs/mail_rules.py
```

Danach die Ordner-Verbesserungen (siehe unten) manuell übernehmen oder den Agenten erneut mit Patch bitten.

## Geplante Verbesserungen (1.3.26)

* IMAP-LIST robuster (quoted names, Hierarchie, kein „/“-Phantom)
* Bis zu **200** Ordner pro Konto (statt 40)
* GMX & Co.: alle auswählbaren Mailboxen
* Mehr LIST/LSUB-Varianten (`\"\" \"*\"`, `%`, LSUB)
* Event-Log: `remote_folders` mit discovered/scan/sample

## 1.3.20 – Übersicht nach „Jetzt löschen“

Nach Vorschau / Löschen siehst du: Lokal gelöscht / Treffer, Remote-Kandidaten, Remote gelöscht, Remote nicht gefunden, pro Konto Ordner.

# Home Assistant Add-on: Mail Archiver

Version **1.3.32**

## 1.3.32 – Remote-Löschen robust (GMX + IMAP)

* IMAP-Suche: mehrere Varianten (CHARSET UTF-8, Klammern, Quotes) – GMX erkennt Treffer zuverlässiger
* Remote-Löschen: stabileres UID STORE/EXPUNGE inkl. Fallback ohne UIDPLUS
* Ordner-Select: Umlaute / IMAP UTF-7 (z. B. Gelöscht)
* Klarere Fehler bei verschlüsseltem oder fehlendem Konto-Passwort
* Mail-Rules-Events zusätzlich in den Add-on-Logs (`[mail-rules]`)

## 1.3.30 – Tailscale/Ingress + Security-UI

* nginx: HTTPS-Erkennung für `*.ts.net`, robustere Redirect- und Cookie-Rewrites unter HA-Ingress
* Session-Cookies: Secure + persistente Keys unter `/data/keys`
* Security-Dashboard: klarere Übersicht (Virenschutz + letzter Regel-Lauf), übersichtlichere Mailregeln

## 1.3.29 – Security-Regeln: Intervall + Lauf-Übersicht

* Mailregeln: Intervall (Minuten) und Automatik an/aus in der Security-UI einstellbar
* Klarere Anzeige von letztem und aktuellem Lauf (lokal/remote, Konten, Regeln)
* Hintergrund-Loop unverändert nutzbar; Einstellungen werden persistent gespeichert

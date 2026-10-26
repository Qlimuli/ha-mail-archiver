# Home Assistant Add-on: Mail Archiver

Version **1.3.30**

## 1.3.30 – Tailscale/Ingress + Security-UI

* nginx: HTTPS-Erkennung für `*.ts.net`, robustere Redirect- und Cookie-Rewrites unter HA-Ingress
* Session-Cookies: Secure + persistente Keys unter `/data/keys`
* Security-Dashboard: klarere Übersicht (Virenschutz + letzter Regel-Lauf), übersichtlichere Mailregeln

## 1.3.29 – Security-Regeln: Intervall + Lauf-Übersicht

* Mailregeln: Intervall (Minuten) und Automatik an/aus in der Security-UI einstellbar
* Klarere Anzeige von letztem und aktuellem Lauf (lokal/remote, Konten, Regeln)
* Hintergrund-Loop unverändert nutzbar; Einstellungen werden persistent gespeichert

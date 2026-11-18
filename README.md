# Home Assistant Add-on: Mail Archiver

Version **1.3.36**

## 1.3.36 – nginx Config Fix

* 1.3.35 startete nicht (`nginx -t` fehlgeschlagen)
* Ursache: `proxy_redirect off` + ungültige `proxy_cookie_flags`-Werte
* Cookie-Flags wieder gültig (`secure`/`nosecure` + `samesite=lax`)
* Ingress-Redirects und Sidebar-Fixes aus 1.3.35 bleiben erhalten

## 1.3.35 – Sidebar Ingress Hang Fix

* nginx: robustere Redirect-Rewrites unter HA-Ingress / Tailscale Funnel
* Cookies: Secure-Flag nur bei HTTPS
* UI-Inject: kurze Panel-Pfade + `fetch`-Patch

## 1.3.32 – Remote-Löschen robust (GMX + IMAP)

* IMAP-Suche / UID STORE / Umlaute / klarere Passwort-Fehler

## 1.3.30 – Tailscale/Ingress + Security-UI

* nginx HTTPS-Erkennung für `*.ts.net`, Cookie-Rewrites, Security-Dashboard

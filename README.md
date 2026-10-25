# Home Assistant Add-on: Mail Archiver

Version **1.3.10**

## 1.3.10 – Altersfilter behoben

Der Filter **Tage** bei Mailregeln nutzt jetzt:

- `COALESCE(ReceivedDate, SentDate)` (falls Empfangsdatum fehlt)
- Kalendervergleich: Datum ≤ heute − N Tage

Add-on **1.3.10** neu bauen, Regel speichern, **Vorschau** prüfen.

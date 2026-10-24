# Home Assistant Add-on: Mail Archiver

Version **1.3.1**

## 1.3.1 – Echter Import-Job nach Chunk-Upload

- Nach Chunk-Upload: Datei aus `/data/import` wird intern an `MailAccounts/ImportEml` gepostet (Session + Anti-Forgery)
- Job erscheint unter **EML-Import-Jobs**
- CLI nur als Fallback

Add-on **1.3.1** neu bauen, Strg+F5.

# Evalanche OIDC Demo

Demo-App zum Testen der Evalanche OIDC/OAuth 2.0 Authentifizierung.

## Umgebungsvariablen

| Variable | Beschreibung |
|---|---|
| `EVALANCHE_DOMAIN` | Deine Evalanche-Domain (z.B. `kunde.evalanche.com`) |
| `CLIENT_ID` | Client ID aus der Evalanche App-Konfiguration |
| `CLIENT_SECRET` | Client Secret aus der Evalanche App-Konfiguration |

## Lokal starten

```bash
npm install
EVALANCHE_DOMAIN=xxx CLIENT_ID=xxx CLIENT_SECRET=xxx npm start
```

## Redirect URL

Nach dem Deployment die angezeigte Redirect URL in Evalanche unter Einstellungen > Applikationen eintragen.

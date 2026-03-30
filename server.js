// =============================================================================
// Evalanche OIDC + REST API Demo
// =============================================================================
//
// Diese Demo-App zeigt zwei Authentifizierungs-Flows gegen Evalanche:
//
// 1. OIDC (OpenID Connect) — Authorization Code Flow
//    Ein Benutzer meldet sich über Evalanche an. Die App erhält ein ID-Token
//    mit Benutzerinformationen (Name, E-Mail, User-ID).
//    Endpunkte:
//      - GET  /auth/oidc/authorize     → Benutzer-Login (Redirect zu Evalanche)
//      - POST /api/auth/v1/oidc/token  → Auth-Code gegen ID-Token tauschen
//
// 2. REST API — Client Credentials Flow
//    Die App authentifiziert sich direkt (ohne Benutzer) mit eigenen Credentials,
//    erhält ein Access-Token und ruft damit die REST-API auf.
//    Endpunkte:
//      - POST /api/auth/v1/flow/client          → Access-Token anfordern
//      - POST /api/rest/vPreview/profiles        → Profile aus einem Pool laden
//
// Token-Caching:
//    Das REST-API Access-Token wird im Speicher gecacht und erst erneuert,
//    wenn es abgelaufen ist. Die GUI zeigt an, ob ein neues Token geholt
//    oder ein bestehendes wiederverwendet wurde.
//
// Umgebungsvariablen:
//    EVALANCHE_DOMAIN  — Evalanche-Hostname (z.B. scnem4.com)
//    CLIENT_ID         — OIDC Client ID
//    CLIENT_SECRET     — OIDC Client Secret
//    API_CLIENT_ID     — REST API Client ID
//    API_CLIENT_SECRET — REST API Client Secret
//    API_SCOPE         — REST API Scope (Standard: api:restpreview)
//    API_POOL_ID       — Pool-ID für den Profil-Abruf (Standard: 29642)
//
// =============================================================================

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Konfiguration -----------------------------------------------------------

const EVALANCHE_DOMAIN = process.env.EVALANCHE_DOMAIN || '';
const CLIENT_ID        = process.env.CLIENT_ID || '';
const CLIENT_SECRET    = process.env.CLIENT_SECRET || '';

const API_CLIENT_ID     = process.env.API_CLIENT_ID || '';
const API_CLIENT_SECRET = process.env.API_CLIENT_SECRET || '';
const API_SCOPE         = process.env.API_SCOPE || 'api:restpreview';
const API_POOL_ID       = parseInt(process.env.API_POOL_ID || '29642', 10);

// --- Token-Cache -------------------------------------------------------------
//
// Das REST-API Access-Token wird hier zwischengespeichert.
// Ein neues Token wird nur angefordert, wenn:
//   - noch kein Token vorhanden ist
//   - das bestehende Token abgelaufen ist (mit 30s Sicherheitspuffer)

const tokenCache = {
  accessToken: null,      // Der Token-String
  expiresAt: 0,           // Unix-Timestamp (ms) wann der Token abläuft
  fetchedAt: 0,           // Unix-Timestamp (ms) wann der Token geholt wurde
};

/**
 * Prüft ob der gecachte Token noch gültig ist (mit 30s Puffer)
 */
function isTokenValid() {
  return tokenCache.accessToken && Date.now() < (tokenCache.expiresAt - 30000);
}

/**
 * Gibt das Alter des gecachten Tokens in Sekunden zurück
 */
function getTokenAgeSec() {
  if (!tokenCache.fetchedAt) return 0;
  return Math.round((Date.now() - tokenCache.fetchedAt) / 1000);
}

// --- CSRF State Store --------------------------------------------------------

const pendingStates = new Map();

function cleanupStates() {
  const fiveMinAgo = Date.now() - 300000;
  for (const [s, ts] of pendingStates) {
    if (ts < fiveMinAgo) pendingStates.delete(s);
  }
}

// --- Hilfsfunktionen ---------------------------------------------------------

function getBaseUrl(req) {
  if (process.env.RAILWAY_PUBLIC_DOMAIN) {
    return `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`;
  }
  return `${req.protocol}://${req.get('host')}`;
}

// =============================================================================
// Routen
// =============================================================================

// --- Startseite --------------------------------------------------------------

app.get('/', (req, res) => {
  const configured = EVALANCHE_DOMAIN && CLIENT_ID && CLIENT_SECRET;

  res.send(renderPage('Evalanche OIDC Demo', `
    <h1>Evalanche OIDC Demo</h1>
    <p class="subtitle">OAuth 2.0 Authorization Code Flow testen</p>

    <div class="status">
      <div class="status-row">
        <span>EVALANCHE_DOMAIN</span>
        ${badge(EVALANCHE_DOMAIN)}
      </div>
      <div class="status-row">
        <span>CLIENT_ID</span>
        ${badge(CLIENT_ID)}
      </div>
      <div class="status-row">
        <span>CLIENT_SECRET</span>
        ${badge(CLIENT_SECRET)}
      </div>
    </div>

    ${configured
      ? `<a href="/auth/login" class="btn">Mit Evalanche anmelden</a>`
      : `<button class="btn btn-disabled" disabled>Bitte Umgebungsvariablen konfigurieren</button>`
    }

    ${configured ? `
    <div class="callback-url">
      <strong>Redirect URL (in Evalanche eintragen):</strong>
      ${getBaseUrl(req)}/oauth/callback
    </div>` : ''}
  `));
});

// --- OIDC Login starten ------------------------------------------------------

app.get('/auth/login', (req, res) => {
  if (!EVALANCHE_DOMAIN || !CLIENT_ID) {
    return res.status(500).send('EVALANCHE_DOMAIN und CLIENT_ID fehlen.');
  }

  // Zufälligen State erzeugen (CSRF-Schutz)
  const state = crypto.randomBytes(32).toString('hex');
  pendingStates.set(state, Date.now());
  cleanupStates();

  const redirectUri = `${getBaseUrl(req)}/oauth/callback`;
  const url = `https://${EVALANCHE_DOMAIN}/auth/oidc/authorize`
    + `?state=${encodeURIComponent(state)}`
    + `&client_id=${encodeURIComponent(CLIENT_ID)}`
    + `&redirect_uri=${encodeURIComponent(redirectUri)}`;

  res.redirect(url);
});

// --- OIDC Callback -----------------------------------------------------------

app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  // Fehler von Evalanche?
  if (error) {
    return res.send(renderErrorPage('Autorisierungsfehler', `Evalanche: ${error}`));
  }

  // State prüfen (CSRF-Schutz)
  if (!state || !pendingStates.has(state)) {
    return res.send(renderErrorPage('Ungültiger State',
      'Der state-Parameter stimmt nicht überein. Möglicher CSRF-Angriff.'));
  }
  pendingStates.delete(state);

  // Auth-Code vorhanden?
  if (!code) {
    return res.send(renderErrorPage('Kein Code', 'Kein Authorization Code erhalten.'));
  }

  try {
    // --- Schritt 1: Auth-Code gegen ID-Token tauschen ---
    const oidcToken = await exchangeCodeForToken(code, getBaseUrl(req));

    // ID-Token dekodieren (ohne Signatur-Validierung, nur für Anzeige)
    const decoded = jwt.decode(oidcToken.id_token, { complete: true });

    // --- Schritt 2: REST-API-Test (Profile laden) ---
    let restResult = null;
    if (API_CLIENT_ID && API_CLIENT_SECRET) {
      restResult = await loadProfiles();
    }

    // --- Ergebnis-Seite rendern ---
    res.send(renderSuccessPage(oidcToken, decoded, restResult));

  } catch (err) {
    res.send(renderErrorPage('Netzwerkfehler', err.message));
  }
});

// --- Logout ------------------------------------------------------------------

app.get('/auth/logout', (_req, res) => {
  res.redirect('/');
});

// =============================================================================
// API-Funktionen
// =============================================================================

/**
 * OIDC: Tauscht den Authorization Code gegen ein ID-Token
 *
 * POST /api/auth/v1/oidc/token
 * Body: { code, redirect_uri, client_id, client_secret, grant_type }
 */
async function exchangeCodeForToken(code, baseUrl) {
  const url = `https://${EVALANCHE_DOMAIN}/api/auth/v1/oidc/token`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      code,
      redirect_uri: `${baseUrl}/oauth/callback`,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'authorization_code',
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`OIDC Token-Fehler (${response.status}): ${JSON.stringify(data)}`);
  }

  return data;
}

/**
 * REST API: Fordert ein Access-Token an (Client Credentials Flow)
 *
 * POST /api/auth/v1/flow/client
 * Body (form-urlencoded): scope, client_id, client_secret
 *
 * Das Token wird gecacht und nur bei Ablauf erneuert.
 * Gibt zurück: { accessToken, wasRefreshed, tokenAgeSec }
 */
async function getRestAccessToken() {
  // Gecachtes Token noch gültig? → Wiederverwenden
  if (isTokenValid()) {
    return {
      accessToken: tokenCache.accessToken,
      wasRefreshed: false,
      tokenAgeSec: getTokenAgeSec(),
    };
  }

  // Neues Token anfordern
  const url = `https://${EVALANCHE_DOMAIN}/api/auth/v1/flow/client`;

  const params = new URLSearchParams();
  params.set('client_id', API_CLIENT_ID);
  params.set('client_secret', API_CLIENT_SECRET);
  if (API_SCOPE) params.set('scope', API_SCOPE);

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`REST Token-Fehler (${response.status}): ${JSON.stringify(data)}`);
  }

  // Token cachen
  tokenCache.accessToken = data.access_token;
  tokenCache.expiresAt = Date.now() + (data.expires_in * 1000);
  tokenCache.fetchedAt = Date.now();

  return {
    accessToken: data.access_token,
    wasRefreshed: true,
    tokenAgeSec: 0,
    expiresIn: data.expires_in,
  };
}

/**
 * REST API: Lädt Profile aus einem Pool (max. 10)
 *
 * Ablauf:
 *   1. POST /api/rest/vPreview/profiles  → Liste von Profil-IDs
 *   2. GET  /api/rest/vPreview/profiles/{id}/details  → Details je Profil
 *
 * Die Details enthalten Attribute wie Vorname, Name, Firma etc.
 */
async function loadProfiles() {
  try {
    // Token holen (aus Cache oder neu)
    const tokenInfo = await getRestAccessToken();
    const headers = {
      'Authorization': `Bearer ${tokenInfo.accessToken}`,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };

    // Schritt 1: Profil-IDs aus dem Pool laden
    const listUrl = `https://${EVALANCHE_DOMAIN}/api/rest/vPreview/profiles`;
    const listResponse = await fetch(listUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ pool_id: API_POOL_ID }),
    });

    const listData = await listResponse.json();

    if (!listResponse.ok) {
      return {
        error: `Profil-Liste fehlgeschlagen (${listResponse.status}): ${JSON.stringify(listData)}`,
        tokenInfo,
      };
    }

    // IDs extrahieren und auf max. 10 begrenzen
    const allIds = extractProfileIds(listData);
    const ids = allIds.slice(0, 10);

    // Schritt 2: Details für jedes Profil laden (parallel)
    const profileDetails = await Promise.all(
      ids.map(async (id) => {
        try {
          const detailUrl = `https://${EVALANCHE_DOMAIN}/api/rest/vPreview/profiles/${id}/details`;
          const detailRes = await fetch(detailUrl, { method: 'GET', headers });
          const detailData = await detailRes.json();
          return { id, data: detailData, ok: detailRes.ok };
        } catch (err) {
          return { id, error: err.message, ok: false };
        }
      })
    );

    return {
      totalCount: allIds.length,
      profiles: profileDetails,
      tokenInfo,
    };

  } catch (err) {
    return { error: err.message };
  }
}

// =============================================================================
// HTML-Rendering
// =============================================================================

const STYLES = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #f5f7fa; color: #333; min-height: 100vh;
         display: flex; align-items: center; justify-content: center; }
  .container { max-width: 700px; width: 100%; margin: 2rem; padding: 2.5rem;
               background: #fff; border-radius: 12px;
               box-shadow: 0 4px 24px rgba(0,0,0,.08); }
  h1 { font-size: 1.5rem; margin-bottom: .3rem; color: #1a1a2e; }
  h2 { font-size: 1.1rem; margin: 1.5rem 0 .75rem; color: #1a1a2e; }
  .subtitle { color: #666; margin-bottom: 2rem; font-size: .95rem; }

  /* Status-Badges */
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px;
           font-size: .75rem; font-weight: 600; }
  .badge-ok { background: #d4edda; color: #155724; }
  .badge-warn { background: #fff3cd; color: #856404; }
  .badge-err { background: #f8d7da; color: #721c24; }

  /* Status-Liste */
  .status { margin-bottom: 2rem; }
  .status-row { display: flex; justify-content: space-between; align-items: center;
                padding: .6rem 0; border-bottom: 1px solid #eee; font-size: .9rem; }

  /* Tabellen */
  table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; table-layout: fixed; }
  td { padding: .5rem .75rem; border-bottom: 1px solid #eee; font-size: .9rem;
       vertical-align: top; word-break: break-all; }
  td:first-child { font-weight: 600; white-space: nowrap; width: 150px;
                    color: #555; word-break: normal; }

  /* Buttons */
  .btn { display: inline-block; padding: .75rem 1.5rem; background: #0066cc;
         color: #fff; border-radius: 8px; text-decoration: none; font-size: .9rem;
         border: none; cursor: pointer; text-align: center; width: 100%; }
  .btn:hover { background: #0052a3; }
  .btn-disabled { background: #ccc; cursor: not-allowed; }

  /* Boxen */
  .token-box { background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px;
               padding: 1rem; font-family: monospace; font-size: .75rem;
               word-break: break-all; max-height: 120px; overflow-y: auto;
               margin-bottom: 1rem; }
  .callback-url { margin-top: 1rem; padding: .75rem; background: #e8f5e9;
                   border-radius: 8px; font-size: .85rem; word-break: break-all; }
  .callback-url strong { display: block; margin-bottom: .3rem; }

  /* REST-Bereich */
  .rest-section { margin-top: 2rem; padding-top: 1.5rem; border-top: 2px solid #e2e8f0; }
  .rest-section h2 { color: #0066cc; }
  .token-status { display: flex; align-items: center; gap: .5rem; margin-bottom: 1rem;
                   padding: .75rem 1rem; border-radius: 8px; font-size: .85rem; }
  .token-fresh { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
  .token-cached { background: #cce5ff; border: 1px solid #b8daff; color: #004085; }
  .error-box { background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 8px;
               padding: 1rem; font-family: monospace; font-size: .8rem;
               word-break: break-all; color: #721c24; margin-bottom: 1rem; }
  .skip-box { margin-top: 1.5rem; padding: .75rem 1rem; background: #fff3cd;
              border: 1px solid #ffeeba; border-radius: 8px; font-size: .85rem;
              color: #856404; margin-bottom: 1.5rem; }

  /* Profil-Karten */
  .profile-grid { display: grid; gap: .75rem; margin-bottom: 1.5rem; }
  .profile-card { background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px;
                   padding: .75rem 1rem; display: flex; align-items: center; gap: .75rem; }
  .profile-avatar { width: 36px; height: 36px; border-radius: 50%; background: #0066cc;
                     color: #fff; display: flex; align-items: center; justify-content: center;
                     font-weight: 600; font-size: .85rem; flex-shrink: 0; }
  .profile-info { min-width: 0; }
  .profile-name { font-weight: 600; font-size: .9rem; }
  .profile-company { font-size: .8rem; color: #666; }
  .profile-id { font-size: .75rem; color: #999; font-family: monospace; }

  /* Fehlerseite */
  .error-title { color: #721c24; }
  .detail { background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px;
            padding: 1rem; font-family: monospace; font-size: .85rem;
            white-space: pre-wrap; word-break: break-all; margin-bottom: 1.5rem; }
`;

function renderPage(title, body) {
  return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>${STYLES}</style>
</head>
<body>
  <div class="container">${body}</div>
</body>
</html>`;
}

function badge(value) {
  return value
    ? '<span class="badge badge-ok">Konfiguriert</span>'
    : '<span class="badge badge-err">Fehlt</span>';
}

// --- Erfolgs-Seite -----------------------------------------------------------

function renderSuccessPage(oidcToken, decoded, restResult) {
  const claims = decoded?.payload || {};

  return renderPage('Authentifizierung erfolgreich', `
    <div style="font-size:2rem;margin-bottom:.5rem;">&#10003;</div>
    <h1>Authentifizierung erfolgreich!</h1>
    <p class="subtitle">Der OIDC-Flow wurde erfolgreich durchlaufen.</p>

    <h2>Benutzer-Informationen (ID Token Claims)</h2>
    <table>
      <tr><td>Subject (sub)</td><td>${claims.sub || '—'}</td></tr>
      <tr><td>E-Mail</td><td>${claims.email || '—'}</td></tr>
      <tr><td>Evalanche User ID</td><td>${claims['eva-user-id'] || '—'}</td></tr>
      <tr><td>Issuer (iss)</td><td>${claims.iss || '—'}</td></tr>
      <tr><td>Audience (aud)</td><td>${Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud || '—'}</td></tr>
      <tr><td>Ausgestellt (iat)</td><td>${formatDate(claims.iat)}</td></tr>
      <tr><td>Gültig bis (exp)</td><td>${formatDate(claims.exp)}</td></tr>
    </table>

    <h2>Token Response</h2>
    <table>
      <tr><td>token_type</td><td>${oidcToken.token_type || '—'}</td></tr>
      <tr><td>expires_in</td><td>${oidcToken.expires_in ? oidcToken.expires_in + ' Sekunden' : '—'}</td></tr>
    </table>

    <h2>ID Token (JWT)</h2>
    <div class="token-box">${oidcToken.id_token || '—'}</div>

    ${renderRestSection(restResult)}

    <a href="/auth/logout" class="btn">Zurück zur Startseite</a>
  `);
}

// --- REST-Ergebnis-Bereich ---------------------------------------------------

function renderRestSection(restResult) {
  if (!restResult) {
    return '<div class="skip-box">REST-API-Test übersprungen (API_CLIENT_ID / API_CLIENT_SECRET nicht konfiguriert)</div>';
  }

  if (restResult.error) {
    return `
    <div class="rest-section">
      <h2>REST-API-Test (Profile)</h2>
      ${renderTokenStatus(restResult.tokenInfo)}
      <div class="error-box">Fehler: ${restResult.error}</div>
    </div>`;
  }

  const { profiles, totalCount, tokenInfo } = restResult;

  return `
  <div class="rest-section">
    <h2>REST-API-Test (Profile aus Pool ${API_POOL_ID})</h2>

    ${renderTokenStatus(tokenInfo)}

    <p style="font-size:.9rem;color:#555;margin-bottom:1rem;">
      ${totalCount} Profile im Pool, ${profiles.length} Details geladen:
    </p>

    <div class="profile-grid">
      ${profiles.map(p => renderProfileCard(p)).join('')}
    </div>
  </div>`;
}

function renderTokenStatus(tokenInfo) {
  if (!tokenInfo) return '';

  if (tokenInfo.wasRefreshed) {
    return `
    <div class="token-status token-fresh">
      <span class="badge badge-ok">Neu</span>
      Neues Access-Token geholt (gültig für ${tokenInfo.expiresIn || '?'}s)
    </div>`;
  }

  return `
  <div class="token-status token-cached">
    <span class="badge badge-warn">Cache</span>
    Bestehendes Access-Token wiederverwendet (Alter: ${tokenInfo.tokenAgeSec}s)
  </div>`;
}

// --- Profil-Hilfsfunktionen --------------------------------------------------

/**
 * Extrahiert Vorname, Name und Firma aus den Profil-Detail-Attributen.
 * Die Attribute kommen als Array: [{ name: "...", value: "..." }, ...]
 * Typische Feldnamen: "Vorname", "Name", "Firma" (können variieren)
 */
function extractProfileFields(detail) {
  const result = detail?.result;
  const attributes = result?.attributes || [];

  // Attribute als Key-Value-Map aufbauen
  const attrs = {};
  for (const attr of attributes) {
    if (attr.name && attr.value) {
      attrs[attr.name.toLowerCase()] = attr.value;
    }
  }

  // Gängige Feldnamen für Vorname, Name, Firma durchprobieren
  const firstName = attrs['vorname'] || attrs['firstname'] || attrs['first_name'] || '';
  const lastName  = attrs['name'] || attrs['nachname'] || attrs['lastname'] || attrs['last_name'] || '';
  const company   = attrs['firma'] || attrs['company'] || attrs['unternehmen'] || attrs['organisation'] || '';
  const email     = attrs['email'] || attrs['e-mail'] || '';

  return { firstName, lastName, company, email };
}

function renderProfileCard(profile) {
  if (!profile.ok) {
    return `
    <div class="profile-card" style="border-color:#f5c6cb;">
      <div class="profile-avatar" style="background:#dc3545;">!</div>
      <div class="profile-info">
        <div class="profile-name">Profil #${profile.id}</div>
        <div class="profile-company" style="color:#dc3545;">Fehler beim Laden</div>
      </div>
    </div>`;
  }

  const { firstName, lastName, company, email } = extractProfileFields(profile.data);
  const displayName = [firstName, lastName].filter(Boolean).join(' ') || `Profil #${profile.id}`;
  const initials = (firstName?.[0] || '') + (lastName?.[0] || '') || '#';

  return `
  <div class="profile-card">
    <div class="profile-avatar">${initials.toUpperCase()}</div>
    <div class="profile-info">
      <div class="profile-name">${displayName}</div>
      ${company ? `<div class="profile-company">${company}</div>` : ''}
      ${email ? `<div class="profile-id">${email}</div>` : ''}
      <div class="profile-id">ID: ${profile.id}</div>
    </div>
  </div>`;
}

function extractProfileIds(data) {
  if (!data) return [];
  // Die API gibt { result: [id1, id2, ...] } zurück
  if (data.result && Array.isArray(data.result)) return data.result;
  if (Array.isArray(data)) return data;
  return [];
}

function formatDate(unixSec) {
  if (!unixSec) return '—';
  return new Date(unixSec * 1000).toLocaleString('de-DE');
}

// --- Fehler-Seite ------------------------------------------------------------

function renderErrorPage(title, detail) {
  return renderPage(`Fehler — ${title}`, `
    <h1 class="error-title">${title}</h1>
    <div class="detail">${detail}</div>
    <a href="/" class="btn">Zurück zur Startseite</a>
  `);
}

// =============================================================================
// Server starten
// =============================================================================

app.listen(PORT, () => {
  console.log(`Evalanche OIDC Demo läuft auf Port ${PORT}`);
});

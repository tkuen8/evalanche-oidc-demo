const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const EVALANCHE_DOMAIN = process.env.EVALANCHE_DOMAIN || '';
const CLIENT_ID = process.env.CLIENT_ID || '';
const CLIENT_SECRET = process.env.CLIENT_SECRET || '';

// Determine base URL for redirect_uri
function getBaseUrl(req) {
  if (process.env.RAILWAY_PUBLIC_DOMAIN) {
    return `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`;
  }
  return `${req.protocol}://${req.get('host')}`;
}

// Store states in memory (fine for demo)
const pendingStates = new Map();

app.get('/', (req, res) => {
  const configured = EVALANCHE_DOMAIN && CLIENT_ID && CLIENT_SECRET;
  const callbackUrl = configured ? `${req.protocol}://${req.get('host')}/oauth/callback` : '';

  res.send(`<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Evalanche OIDC Demo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { max-width: 560px; width: 100%; margin: 2rem; padding: 2.5rem; background: #fff; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.08); }
    h1 { font-size: 1.5rem; margin-bottom: .5rem; color: #1a1a2e; }
    .subtitle { color: #666; margin-bottom: 2rem; font-size: .95rem; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: .75rem; font-weight: 600; }
    .badge-ok { background: #d4edda; color: #155724; }
    .badge-missing { background: #f8d7da; color: #721c24; }
    .status { margin-bottom: 2rem; }
    .status-row { display: flex; justify-content: space-between; align-items: center; padding: .6rem 0; border-bottom: 1px solid #eee; font-size: .9rem; }
    .btn { display: inline-block; padding: .85rem 2rem; background: #0066cc; color: #fff; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; text-decoration: none; text-align: center; width: 100%; transition: background .2s; }
    .btn:hover { background: #0052a3; }
    .btn:disabled, .btn-disabled { background: #ccc; cursor: not-allowed; }
    .info { margin-top: 1.5rem; padding: 1rem; background: #f0f4ff; border-radius: 8px; font-size: .85rem; color: #555; }
    .info code { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: .8rem; word-break: break-all; }
    .callback-url { margin-top: 1rem; padding: .75rem; background: #e8f5e9; border-radius: 8px; font-size: .85rem; word-break: break-all; }
    .callback-url strong { display: block; margin-bottom: .3rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Evalanche OIDC Demo</h1>
    <p class="subtitle">OAuth 2.0 Authorization Code Flow testen</p>

    <div class="status">
      <div class="status-row">
        <span>EVALANCHE_DOMAIN</span>
        <span class="badge ${EVALANCHE_DOMAIN ? 'badge-ok">Konfiguriert' : 'badge-missing">Fehlt'}"</span>
      </div>
      <div class="status-row">
        <span>CLIENT_ID</span>
        <span class="badge ${CLIENT_ID ? 'badge-ok">Konfiguriert' : 'badge-missing">Fehlt'}"</span>
      </div>
      <div class="status-row">
        <span>CLIENT_SECRET</span>
        <span class="badge ${CLIENT_SECRET ? 'badge-ok">Konfiguriert' : 'badge-missing">Fehlt'}"</span>
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

  </div>
</body>
</html>`);
});

app.get('/auth/login', (req, res) => {
  if (!EVALANCHE_DOMAIN || !CLIENT_ID) {
    return res.status(500).send('EVALANCHE_DOMAIN und CLIENT_ID müssen konfiguriert sein.');
  }

  const state = crypto.randomBytes(32).toString('hex');
  pendingStates.set(state, Date.now());

  // Cleanup old states (> 5 min)
  for (const [s, ts] of pendingStates) {
    if (Date.now() - ts > 300000) pendingStates.delete(s);
  }

  const redirectUri = `${getBaseUrl(req)}/oauth/callback`;
  const authorizeUrl = `https://${EVALANCHE_DOMAIN}/auth/oidc/authorize?state=${encodeURIComponent(state)}&client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(redirectUri)}`;

  res.redirect(authorizeUrl);
});

app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.send(errorPage('Autorisierungsfehler', `Evalanche hat einen Fehler zurückgegeben: ${error}`));
  }

  if (!state || !pendingStates.has(state)) {
    return res.send(errorPage('Ungültiger State', 'Der state-Parameter stimmt nicht überein (möglicher CSRF-Angriff).'));
  }
  pendingStates.delete(state);

  if (!code) {
    return res.send(errorPage('Kein Code', 'Kein Authorization Code erhalten.'));
  }

  try {
    const redirectUri = `${getBaseUrl(req)}/oauth/callback`;
    const tokenUrl = `https://${EVALANCHE_DOMAIN}/api/auth/v1/oidc/token`;

    const tokenResponse = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        redirect_uri: redirectUri,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
      }),
    });

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      return res.send(errorPage('Token-Fehler', `Status ${tokenResponse.status}: ${JSON.stringify(tokenData, null, 2)}`));
    }

    // Decode the ID token (without verification for demo display)
    const decoded = jwt.decode(tokenData.id_token, { complete: true });

    res.send(successPage(tokenData, decoded));
  } catch (err) {
    res.send(errorPage('Netzwerkfehler', `Fehler beim Token-Tausch: ${err.message}`));
  }
});

app.get('/auth/logout', (req, res) => {
  res.redirect('/');
});

function successPage(tokenData, decoded) {
  const claims = decoded?.payload || {};
  return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentifizierung erfolgreich</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { max-width: 640px; width: 100%; margin: 2rem; padding: 2.5rem; background: #fff; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.08); }
    h1 { font-size: 1.5rem; margin-bottom: .3rem; color: #155724; }
    .subtitle { color: #666; margin-bottom: 2rem; }
    h2 { font-size: 1.1rem; margin: 1.5rem 0 .75rem; color: #1a1a2e; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; table-layout: fixed; }
    td { padding: .5rem .75rem; border-bottom: 1px solid #eee; font-size: .9rem; vertical-align: top; word-break: break-all; }
    td:first-child { font-weight: 600; white-space: nowrap; width: 140px; color: #555; word-break: normal; }
    .token-box { background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; font-family: monospace; font-size: .75rem; word-break: break-all; max-height: 120px; overflow-y: auto; margin-bottom: 1rem; }
    .btn { display: inline-block; padding: .75rem 1.5rem; background: #0066cc; color: #fff; border-radius: 8px; text-decoration: none; font-size: .9rem; }
    .btn:hover { background: #0052a3; }
    .success-icon { font-size: 2rem; margin-bottom: .5rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">&#10003;</div>
    <h1>Authentifizierung erfolgreich!</h1>
    <p class="subtitle">Der OIDC-Flow wurde erfolgreich durchlaufen.</p>

    <h2>Benutzer-Informationen (ID Token Claims)</h2>
    <table>
      <tr><td>Subject (sub)</td><td>${claims.sub || '—'}</td></tr>
      <tr><td>E-Mail</td><td>${claims.email || '—'}</td></tr>
      <tr><td>Evalanche User ID</td><td>${claims['eva-user-id'] || '—'}</td></tr>
      <tr><td>Issuer (iss)</td><td>${claims.iss || '—'}</td></tr>
      <tr><td>Audience (aud)</td><td>${Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud || '—'}</td></tr>
      <tr><td>Ausgestellt (iat)</td><td>${claims.iat ? new Date(claims.iat * 1000).toLocaleString('de-DE') : '—'}</td></tr>
      <tr><td>Gültig bis (exp)</td><td>${claims.exp ? new Date(claims.exp * 1000).toLocaleString('de-DE') : '—'}</td></tr>
    </table>

    <h2>Token Response</h2>
    <table>
      <tr><td>token_type</td><td>${tokenData.token_type || '—'}</td></tr>
      <tr><td>expires_in</td><td>${tokenData.expires_in ? tokenData.expires_in + ' Sekunden' : '—'}</td></tr>
    </table>

    <h2>ID Token (JWT)</h2>
    <div class="token-box">${tokenData.id_token || '—'}</div>

    <a href="/auth/logout" class="btn">Zurück zur Startseite</a>
  </div>
</body>
</html>`;
}

function errorPage(title, detail) {
  return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Fehler — ${title}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { max-width: 560px; width: 100%; margin: 2rem; padding: 2.5rem; background: #fff; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.08); }
    h1 { font-size: 1.5rem; margin-bottom: .75rem; color: #721c24; }
    .detail { background: #f8f9fa; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; font-family: monospace; font-size: .85rem; white-space: pre-wrap; word-break: break-all; margin-bottom: 1.5rem; }
    .btn { display: inline-block; padding: .75rem 1.5rem; background: #0066cc; color: #fff; border-radius: 8px; text-decoration: none; font-size: .9rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${title}</h1>
    <div class="detail">${detail}</div>
    <a href="/" class="btn">Zurück zur Startseite</a>
  </div>
</body>
</html>`;
}

app.listen(PORT, () => {
  console.log(`Evalanche OIDC Demo running on port ${PORT}`);
});

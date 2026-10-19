// Cloudflare Pages Function: POST /api/token
// Exchanges the one-time authorization code for an access token (must run on the backend).

const TOKEN_URL = 'https://auth.deriv.com/oauth2/token';
const ACCOUNTS_URL = 'https://api.derivws.com/trading/v1/options/accounts';

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status: status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });

export async function onRequestPost({ request }) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: 'invalid_json' }, 400);
  }
  const { code, code_verifier, client_id, redirect_uri } = body || {};

  if (!code || !code_verifier || !client_id || !redirect_uri) {
    return json({ error: 'missing_fields' }, 400);
  }

  try {
    // 1) Exchange the code for an access token.
    const tokenRes = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: client_id,
        code: code,
        code_verifier: code_verifier,
        redirect_uri: redirect_uri
      }).toString()
    });
    const token = await tokenRes.json().catch(() => ({}));

    if (!tokenRes.ok || !token.access_token) {
      return json({
        error: token.error || 'token_exchange_failed',
        error_description: token.error_description || ''
      }, 400);
    }

    const out = {
      access_token: token.access_token,
      expires_in: token.expires_in,
      token_type: token.token_type
    };

    // 2) Quick check that the token works: list the user's accounts.
    //    A failure here never blocks the login. Safe to delete this block later.
    try {
      const accRes = await fetch(ACCOUNTS_URL, {
        headers: {
          'Authorization': 'Bearer ' + token.access_token,
          'Deriv-App-ID': client_id,
          'Accept': 'application/json'
        }
      });
      const accData = await accRes.json().catch(() => null);
      if (accRes.ok) {
        out.accounts = accData;
      } else {
        out.accounts_error = 'HTTP ' + accRes.status + (accData ? ' ' + JSON.stringify(accData).slice(0, 300) : '');
      }
    } catch (e) {
      out.accounts_error = e.message;
    }

    return json(out);
  } catch (e) {
    return json({ error: 'upstream_error', error_description: e.message }, 502);
  }
}

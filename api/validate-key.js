// api/validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  const key = req.query.key;
  if (!key) {
    return res.status(400).json({ error: 'Missing key parameter' });
  }

  // Grab env
  const GIST_TOKEN = process.env.GIST_TOKEN;
  const GIST_ID    = process.env.GIST_ID;
  const rawKey     = process.env.RSA_PRIVATE_KEY;
  // If you ended up pasting literal "\n" sequences, you can transform here:
  const PRIV_KEY = rawKey?.includes("\\n") ? rawKey.replace(/\\n/g, "\n") : rawKey;

  // Debug: log presence (remove or lower in prod later)
  console.log('>> ENV presence:', {
    GIST_TOKEN: !!GIST_TOKEN,
    GIST_ID: !!GIST_ID,
    RSA_PRIVATE_KEY: !!PRIV_KEY
  });
  if (!GIST_TOKEN || !GIST_ID || !PRIV_KEY) {
    console.error('>> Server misconfigured: missing env var');
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // Build URL correctly
  const gistUrl = `https://api.github.com/gists/${GIST_ID}`;
  let gistResp;
  try {
    gistResp = await fetch(gistUrl, {
      headers: {
        'Authorization': `token ${GIST_TOKEN}`,
        'User-Agent': 'key-validator-api',
        'Accept': 'application/vnd.github.v3+json'
      }
    });
  } catch (err) {
    console.error('Network error fetching gist:', err);
    return res.status(502).json({ error: 'Failed to fetch keys (network)' });
  }

  if (!gistResp.ok) {
    const text = await gistResp.text();
    console.error('GitHub API error:', gistResp.status, text);
    return res.status(502).json({
      error: 'Failed to fetch keys',
      status: gistResp.status,
      body: text
    });
  }

  let gistJson;
  try {
    gistJson = await gistResp.json();
  } catch (err) {
    console.error('Invalid JSON from GitHub:', err);
    return res.status(502).json({ error: 'Invalid JSON from GitHub' });
  }

  const file = gistJson.files?.['keys.txt'];
  let found = false, redeemed_by = null, redeemed_at = null;
  if (file && typeof file.content === 'string') {
    for (let line of file.content.split('\n')) {
      line = line.trim();
      if (!line || line.startsWith('#')) continue;
      const parts = line.split(',', 4);
      const [k, roleId, by, at] = parts;
      if (k === key) {
        found = true;
        if (by) {
          redeemed_by = by;
          redeemed_at = at;
        }
        break;
      }
    }
  } else {
    console.warn('keys.txt missing or empty in gist:', gistJson.files);
  }

  const valid = found && redeemed_by === null;
  const payload = { key, valid, redeemed_by, redeemed_at };
  const payloadJson = JSON.stringify(payload);

  try {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(payloadJson);
    sign.end();
    const signature = sign.sign(PRIV_KEY, 'base64');
    return res.status(200).json({ payload, signature });
  } catch (err) {
    console.error('Signing error', err);
    return res.status(500).json({ error: 'Signing failed' });
  }
}

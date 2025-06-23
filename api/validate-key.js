// api/validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  const key = req.query.key;
  if (!key) return res.status(400).json({ error: 'Missing key parameter' });

  const GIST_TOKEN = process.env.GIST_TOKEN;
  const GIST_ID    = process.env.GIST_ID;
  const PRIV_KEY   = process.env.RSA_PRIVATE_KEY; // full PEM

  if (!GIST_TOKEN || !GIST_ID || !PRIV_KEY) {
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // Fetch private gist
  const gistUrl = `https://api.github.com/gists/${GIST_ID}`;
  const gistResp = await fetch(gistUrl, {
    headers: {
      'Authorization': `token ${GIST_TOKEN}`,
      'Accept': 'application/vnd.github.v3+json'
    }
  });
  if (!gistResp.ok) {
    return res.status(502).json({ error: 'Failed to fetch keys' });
  }
  const gist = await gistResp.json();
  const file = gist.files?.['keys.txt'];
  let found = false, redeemed_by = null, redeemed_at = null;
  if (file && file.content) {
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
  }
  // decide valid only if found and not redeemed
  const valid = found && redeemed_by === null;
  const payload = { key, valid, redeemed_by, redeemed_at };
  const payloadJson = JSON.stringify(payload);

  // Sign with RSA private key
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

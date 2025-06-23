// api/validate-key.js

export default async function handler(req, res) {
  const key = req.query.key;
  if (!key) {
    return res.status(400).json({ error: 'Missing key parameter' });
  }

  const GIST_TOKEN = process.env.GIST_TOKEN;
  const GIST_ID    = process.env.GIST_ID;
  const PRIV_KEY   = process.env.RSA_PRIVATE_KEY;

  if (!GIST_TOKEN || !GIST_ID || !PRIV_KEY) {
    console.error('Misconfigured env:', { GIST_TOKEN: !!GIST_TOKEN, GIST_ID, PRIV_KEY: !!PRIV_KEY });
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // 1) Fetch private gist
  const gistUrl = `https://api.github.com/gists/${GIST_ID}`;
  let gistResp;
  try {
    gistResp = await fetch(gistUrl, {
      headers: {
        'Authorization': `token ${GIST_TOKEN}`,
        // 'Accept': 'application/vnd.github.v3+json' // optional
      }
    });
  } catch (err) {
    console.error('Fetch error:', err);
    return res.status(502).json({ error: 'Failed to fetch keys (network error)' });
  }

  const text = await gistResp.text();
  if (!gistResp.ok) {
    console.error('GitHub API error:', gistResp.status, text);
    // If GitHub returns something like 415 or 406 Invalid API version, we'll see it here.
    return res.status(502).json({
      error: 'Failed to fetch keys',
      status: gistResp.status,
      body: text
    });
  }

  let gist;
  try {
    gist = JSON.parse(text);
  } catch (err) {
    console.error('Invalid JSON from GitHub:', err, text);
    return res.status(502).json({ error: 'Invalid JSON from GitHub' });
  }

  const file = gist.files?.['keys.txt'];
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
    console.warn('keys.txt missing or empty in gist:', gist.files);
  }

  const valid = found && redeemed_by === null;
  const payload = { key, valid, redeemed_by, redeemed_at };
  const payloadJson = JSON.stringify(payload);

  // 2) Sign with RSA private key
  try {
    // In Node.js, crypto.createSign is synchronous
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(payloadJson);
    sign.end();
    const signature = sign.sign(PRIV_KEY, 'base64');
    return res.status(200).json({ payload, signature });
  } catch (err) {
    console.error('Signing error:', err);
    return res.status(500).json({ error: 'Signing failed' });
  }
}

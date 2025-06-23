// api/validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  const GIST_TOKEN = process.env.GIST_TOKEN;
  const GIST_ID    = process.env.GIST_ID;
  const rawKey     = process.env.RSA_PRIVATE_KEY;
  const PRIV_KEY   = rawKey?.includes("\\n") ? rawKey.replace(/\\n/g, "\n") : rawKey;

  if (!GIST_TOKEN || !GIST_ID || !PRIV_KEY) {
    console.error('Server misconfigured: missing env var');
    // For POST, we want plain-text invalid; for GET we return JSON error
    if (req.method === 'POST') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // Utility: fetch gist and check raw key presence/unredeemed
  async function isKeyValidInGist(key) {
    try {
      const gistResp = await fetch(`https://api.github.com/gists/${GIST_ID}`, {
        headers: {
          'Authorization': `token ${GIST_TOKEN}`,
          'User-Agent': 'key-validator-api',
          'Accept': 'application/vnd.github.v3+json'
        }
      });
      if (!gistResp.ok) {
        console.error('GitHub API error fetching gist:', gistResp.status);
        return false;
      }
      const gistJson = await gistResp.json();
      const file = gistJson.files?.['keys.txt'];
      if (!file || typeof file.content !== 'string') {
        console.warn('keys.txt missing or empty in gist');
        return false;
      }
      for (let line of file.content.split('\n')) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;
        const parts = line.split(',', 4);
        const [k, roleId, by, at] = parts;
        if (k === key) {
          if (by && by.trim() !== '') {
            // already redeemed
            return false;
          }
          return true;
        }
      }
      return false;
    } catch (err) {
      console.error('Error in isKeyValidInGist:', err);
      return false;
    }
  }

  // Utility: verify signature over payload using public key derived from PRIV_KEY
  function verifySignature(payloadObj, signatureB64) {
    try {
      const publicKeyObj = crypto.createPublicKey(PRIV_KEY);
      // Re-create JSON string exactly as JS did: JSON.stringify(payloadObj)
      const payloadJson = JSON.stringify(payloadObj);
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(payloadJson);
      verifier.end();
      const sigBuf = Buffer.from(signatureB64, 'base64');
      return verifier.verify(publicKeyObj, sigBuf);
    } catch (err) {
      console.error('Signature verification error:', err);
      return false;
    }
  }

  if (req.method === 'POST') {
    // Expect JSON body: { payload: {...}, signature: "base64..." }
    let body;
    try {
      body = await parseJsonBody(req);
    } catch (e) {
      console.error('Failed to parse JSON body:', e);
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    const { payload, signature } = body;
    if (!payload || typeof payload !== 'object' || !signature || typeof signature !== 'string') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Verify signature
    const sigOk = verifySignature(payload, signature);
    if (!sigOk) {
      console.warn('Signature invalid');
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Extract key
    const key = payload.key;
    if (!key || typeof key !== 'string') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Check in gist
    const keyOk = await isKeyValidInGist(key);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(keyOk ? 'valid' : 'invalid');
  }

  if (req.method === 'GET') {
    // Legacy: generate license JSON { payload, signature }
    const key = req.query.key;
    if (!key) {
      return res.status(400).json({ error: 'Missing key parameter' });
    }
    const keyOk = await isKeyValidInGist(key);
    const payload = { key, valid: keyOk, redeemed_by: null, redeemed_at: null };
    const payloadJson = JSON.stringify(payload);
    try {
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(payloadJson);
      signer.end();
      const signature = signer.sign(PRIV_KEY, 'base64');
      return res.status(200).json({ payload, signature });
    } catch (err) {
      console.error('Signing error:', err);
      return res.status(500).json({ error: 'Signing failed' });
    }
  }

  // Method not allowed
  res.setHeader('Allow', 'GET, POST');
  if (req.method === 'POST') {
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send('invalid');
  }
  return res.status(405).json({ error: 'Method not allowed' });
}

// Helper to parse JSON body in Vercel serverless Node environment
async function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 1e6) {
        req.socket.destroy();
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => {
      try {
        const obj = JSON.parse(data);
        resolve(obj);
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', err => {
      reject(err);
    });
  });
}

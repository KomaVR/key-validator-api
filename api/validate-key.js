// api/validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  // Common: load env
  const GIST_TOKEN = process.env.GIST_TOKEN;
  const GIST_ID    = process.env.GIST_ID;
  const rawKey     = process.env.RSA_PRIVATE_KEY;
  const PRIV_KEY   = rawKey?.includes("\\n") ? rawKey.replace(/\\n/g, "\n") : rawKey;

  if (!GIST_TOKEN || !GIST_ID || !PRIV_KEY) {
    console.error('Server misconfigured: missing env var');
    // Always return 200 with invalid in body or a JSON error? Here we return JSON error.
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // Helper: fetch and check the gist for a raw key
  async function isKeyValidInGist(key) {
    // Fetch gist
    let gistResp;
    try {
      gistResp = await fetch(`https://api.github.com/gists/${GIST_ID}`, {
        headers: {
          'Authorization': `token ${GIST_TOKEN}`,
          'User-Agent': 'key-validator-api',
          'Accept': 'application/vnd.github.v3+json'
        }
      });
    } catch (err) {
      console.error('Network error fetching gist:', err);
      throw new Error('Failed to fetch keys (network)');
    }
    if (!gistResp.ok) {
      const text = await gistResp.text().catch(()=>'');
      console.error('GitHub API error:', gistResp.status, text);
      throw new Error('Failed to fetch keys from GitHub');
    }
    let gistJson;
    try {
      gistJson = await gistResp.json();
    } catch (err) {
      console.error('Invalid JSON from GitHub:', err);
      throw new Error('Invalid JSON from GitHub');
    }
    const file = gistJson.files?.['keys.txt'];
    if (!file || typeof file.content !== 'string') {
      console.warn('keys.txt missing or empty in gist:', gistJson.files);
      return false;
    }
    // Parse lines: raw key or comma-separated: [key, roleId, redeemed_by, redeemed_at]
    for (let line of file.content.split('\n')) {
      line = line.trim();
      if (!line || line.startsWith('#')) continue;
      const parts = line.split(',', 4);
      const [k, roleId, by, at] = parts;
      if (k === key) {
        // if redeemed_by present (non-empty), treat as invalid
        if (by && by.trim() !== '') {
          return false;
        }
        return true;
      }
    }
    return false;
  }

  // Helper: verify signature given payload object and base64 signature, using public key derived from private
  function verifySignature(payloadObj, signatureB64) {
    try {
      // Derive public key from the private key
      const publicKeyObj = crypto.createPublicKey(PRIV_KEY);
      // Re-create JSON string exactly as server originally signed: JSON.stringify(payloadObj)
      // JSON.stringify in JS has no spaces after colon, so we must reproduce that:
      const payloadJson = JSON.stringify(payloadObj);
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(payloadJson);
      verifier.end();
      const sigBuf = Buffer.from(signatureB64, 'base64');
      const ok = verifier.verify(publicKeyObj, sigBuf);
      return ok;
    } catch (err) {
      console.error('Error during signature verification:', err);
      return false;
    }
  }

  // Handle POST: expect JSON body { payload: {...}, signature: "base64..." }
  if (req.method === 'POST') {
    let body;
    try {
      body = await parseJsonBody(req);
    } catch (e) {
      console.error('Failed to parse JSON body:', e);
      return res.status(400).json({ valid: false, error: 'Invalid JSON body' });
    }
    const { payload, signature } = body;
    if (!payload || typeof payload !== 'object' || !signature || typeof signature !== 'string') {
      return res.status(400).json({ valid: false, error: 'Body must have payload object and signature string' });
    }
    // Verify signature
    const sigOk = verifySignature(payload, signature);
    if (!sigOk) {
      return res.status(200).json({ valid: false, error: 'Signature invalid' });
    }
    // Extract key from payload
    const key = payload.key;
    if (!key || typeof key !== 'string') {
      return res.status(400).json({ valid: false, error: 'Payload missing key field' });
    }
    // Check key in gist
    let keyOk;
    try {
      keyOk = await isKeyValidInGist(key);
    } catch (err) {
      console.error('Error checking key in gist:', err);
      return res.status(500).json({ valid: false, error: 'Error checking key' });
    }
    return res.status(200).json({ valid: keyOk });
  }

  // Handle GET: legacy ?key=... → simply sign and return payload+signature, or return JSON payload+signature
  if (req.method === 'GET') {
    const key = req.query.key;
    if (!key) {
      return res.status(400).json({ error: 'Missing key parameter' });
    }
    // Check raw key in gist
    let keyOk;
    try {
      keyOk = await isKeyValidInGist(key);
    } catch (err) {
      console.error('Error checking key in gist:', err);
      return res.status(500).json({ error: 'Error checking key' });
    }
    // Build payload: same structure as before
    const payload = { key, valid: keyOk, redeemed_by: null, redeemed_at: null };
    const payloadJson = JSON.stringify(payload);
    // Sign with private key
    try {
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(payloadJson);
      signer.end();
      const signature = signer.sign(PRIV_KEY, 'base64');
      return res.status(200).json({ payload, signature });
    } catch (err) {
      console.error('Signing error', err);
      return res.status(500).json({ error: 'Signing failed' });
    }
  }

  // Other methods not allowed
  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
}

// Utility to parse JSON body in serverless environment
async function parseJsonBody(req) {
  // In Vercel Node.js functions, req is a standard Node IncomingMessage with a readable stream
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      // Limit size if you wish
      if (data.length > 1e6) {
        // Flood attack or too big
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

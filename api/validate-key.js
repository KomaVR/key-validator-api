// api/validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  const GIST_TOKEN  = process.env.GIST_TOKEN;
  const GIST_ID     = process.env.GIST_ID;
  const HMAC_SECRET = process.env.HMAC_SECRET;  // must match Python bot’s HMAC_SECRET

  if (!GIST_TOKEN || !GIST_ID || !HMAC_SECRET) {
    console.error('Server misconfigured: missing GIST_TOKEN, GIST_ID, or HMAC_SECRET');
    if (req.method === 'POST') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // Fetch gist and check if key exists (unredeemed).
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
      // Each line is a raw key
      for (let line of file.content.split('\n')) {
        line = line.trim();
        if (!line) continue;
        if (line === key) {
          return true;
        }
      }
      return false;
    } catch (err) {
      console.error('Error in isKeyValidInGist:', err);
      return false;
    }
  }

  // Verify HMAC signature over payloadObj = { key }
  function verifyHmacSignature(payloadObj, signatureHex) {
    try {
      const payloadJson = JSON.stringify(payloadObj);
      const hmac = crypto.createHmac('sha256', HMAC_SECRET);
      hmac.update(payloadJson);
      const expectedHex = hmac.digest('hex');
      const sigBuf = Buffer.from(signatureHex, 'hex');
      const expBuf = Buffer.from(expectedHex, 'hex');
      if (sigBuf.length !== expBuf.length) {
        return false;
      }
      return crypto.timingSafeEqual(sigBuf, expBuf);
    } catch (err) {
      console.error('HMAC verification error:', err);
      return false;
    }
  }

  if (req.method === 'POST') {
    // Expect JSON body: { payload: { key: "..." }, signature: "hexstring" }
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
    const key = payload.key;
    if (!key || typeof key !== 'string') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Verify HMAC over {"key": "..."}
    if (!verifyHmacSignature({ key }, signature)) {
      console.warn('Signature invalid');
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Check key in gist
    const keyOk = await isKeyValidInGist(key);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(keyOk ? 'valid' : 'invalid');
  }

  // Disallow GET for validation. If you need a GET route for signing, handle separately.
  res.setHeader('Allow', 'POST');
  if (req.method === 'GET') {
    // Optional: return 405 or a message
    return res.status(405).json({ error: 'Method not allowed' });
  }
  // Other methods
  return res.status(405).json({ error: 'Method not allowed' });
}

// Helper to parse JSON body from Node.js req
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

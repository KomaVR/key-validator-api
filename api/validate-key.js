// validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  const GIST_TOKEN  = process.env.GIST_TOKEN;
  const GIST_ID     = process.env.GIST_ID;
  const HMAC_SECRET = process.env.HMAC_SECRET;

  if (!GIST_TOKEN || !GIST_ID || !HMAC_SECRET) {
    console.error('Server misconfigured: missing GIST_TOKEN, GIST_ID, or HMAC_SECRET');
    if (req.method === 'POST') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // Helper to parse JSON body
  async function parseJsonBody(req) {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => data += chunk);
      req.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
      req.on('error', err => reject(err));
    });
  }

  // Check key in gist
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
      const lines = file.content.split('\n');
      // Debug: log lines with quotes to spot whitespace
      console.log('DEBUG gist lines:', lines.map(l => `"${l}"`));
      for (let rawLine of lines) {
        let line = rawLine.trim();
        if (!line) continue;
        console.log(`DEBUG comparing line "${line}" to key "${key}"`);
        if (line === key) {
          console.log('DEBUG key found in gist.');
          return true;
        }
      }
      console.log('DEBUG key NOT found in gist.');
      return false;
    } catch (err) {
      console.error('Error in isKeyValidInGist:', err);
      return false;
    }
  }

  // Verify HMAC over payloadObj = { key }
  function verifyHmacSignature(payloadObj, signatureHex) {
    try {
      const payloadJson = JSON.stringify(payloadObj); 
      console.log('DEBUG payloadJson for HMAC:', payloadJson);
      const hmacObj = crypto.createHmac('sha256', HMAC_SECRET);
      hmacObj.update(payloadJson);
      const expectedHex = hmacObj.digest('hex');
      console.log('DEBUG expectedHex:', expectedHex, 'received signatureHex:', signatureHex);
      const sigBuf = Buffer.from(signatureHex, 'hex');
      const expBuf = Buffer.from(expectedHex, 'hex');
      if (sigBuf.length !== expBuf.length) {
        console.warn('DEBUG HMAC length mismatch');
        return false;
      }
      const ok = crypto.timingSafeEqual(sigBuf, expBuf);
      console.log('DEBUG timingSafeEqual result:', ok);
      return ok;
    } catch (err) {
      console.error('HMAC verification error:', err);
      return false;
    }
  }

  if (req.method === 'POST') {
    // Ensure client sends header Content-Type: application/json
    let body;
    try {
      body = await parseJsonBody(req);
    } catch (e) {
      console.error('Failed to parse JSON body:', e);
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    console.log('DEBUG parsed body:', body);
    const { payload, signature } = body;
    if (!payload || typeof payload !== 'object' || !signature || typeof signature !== 'string') {
      console.warn('Invalid body shape:', body);
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    const key = payload.key;
    if (!key || typeof key !== 'string') {
      console.warn('payload.key invalid:', payload);
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Verify HMAC over {"key":"..."}
    if (!verifyHmacSignature({ key }, signature)) {
      console.warn('Signature invalid for key:', key);
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Check gist
    const keyOk = await isKeyValidInGist(key);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(keyOk ? 'valid' : 'invalid');
  }

  // Only POST allowed
  res.setHeader('Allow', 'POST');
  return res.status(405).json({ error: 'Method not allowed' });
}

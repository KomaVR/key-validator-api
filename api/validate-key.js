// validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  const GIST_TOKEN  = process.env.GIST_TOKEN;
  const GIST_ID     = process.env.GIST_ID;
  const HMAC_SECRET = process.env.HMAC_SECRET;

  if (!GIST_TOKEN || !GIST_ID || !HMAC_SECRET) {
    console.error('Server misconfigured: missing GIST_TOKEN, GIST_ID, or HMAC_SECRET');
    if (req.method === 'POST' || req.method === 'GET') {
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

  // Check key in gist (one-per-line in keys.txt)
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
      for (let rawLine of lines) {
        let line = rawLine.trim();
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

  // Verify HMAC over payloadObj = { key }
  function verifyHmacSignature(payloadObj, signatureHex) {
    try {
      const payloadJson = JSON.stringify(payloadObj);
      const hmacObj = crypto.createHmac('sha256', HMAC_SECRET);
      hmacObj.update(payloadJson);
      const expectedHex = hmacObj.digest('hex');
      const sigBuf = Buffer.from(signatureHex, 'hex');
      const expBuf = Buffer.from(expectedHex, 'hex');
      if (sigBuf.length !== expBuf.length) return false;
      return crypto.timingSafeEqual(sigBuf, expBuf);
    } catch (err) {
      console.error('HMAC verification error:', err);
      return false;
    }
  }

  if (req.method === 'POST') {
    // Validate a license file
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
    // Verify HMAC over {"key":"..."}
    if (!verifyHmacSignature({ key }, signature)) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Check gist
    const keyOk = await isKeyValidInGist(key);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(keyOk ? 'valid' : 'invalid');
  }

  if (req.method === 'GET') {
    // Generate a license if key is valid
    const key = req.query.key;
    if (!key || typeof key !== 'string') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(400).send('invalid');
    }
    const keyOk = await isKeyValidInGist(key);
    if (!keyOk) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Build license: payload={"key":key}, issued_at now, signature=HMAC
    const issued_at = new Date().toISOString();
    const payloadObj = { key };
    const payloadJson = JSON.stringify(payloadObj);
    const hmacObj = crypto.createHmac('sha256', HMAC_SECRET);
    hmacObj.update(payloadJson);
    const signatureHex = hmacObj.digest('hex');
    const licenseBlob = {
      payload: payloadObj,
      issued_at,
      signature: signatureHex
    };
    const respText = JSON.stringify(licenseBlob);
    res.setHeader('Content-Type', 'application/json');
    return res.status(200).send(respText);
  }

  // Other methods not allowed
  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
}

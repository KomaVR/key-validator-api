// validate-key.js
import fetch from 'node-fetch';
import crypto from 'crypto';

export default async function handler(req, res) {
  const GIST_TOKEN  = process.env.GIST_TOKEN;
  const GIST_ID     = process.env.GIST_ID;
  const HMAC_SECRET = process.env.HMAC_SECRET;

  if (!GIST_TOKEN || !GIST_ID || !HMAC_SECRET) {
    console.error('Server misconfigured: missing env vars');
    if (req.method === 'POST' || req.method === 'GET') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  // Helper: parse JSON POST body
  async function parseJsonBody(req) {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => data += chunk);
      req.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
      req.on('error', err => reject(err));
    });
  }

  // Check if key exists in gist (one per line)
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
        console.error('GitHub fetch error:', gistResp.status);
        return false;
      }
      const gistJson = await gistResp.json();
      const file = gistJson.files?.['keys.txt'];
      if (!file || typeof file.content !== 'string') {
        console.warn('keys.txt missing or empty');
        return false;
      }
      const lines = file.content.split('\n').map(l => l.trim()).filter(l => l);
      // Debug: uncomment if needed
      // console.log('DEBUG gist lines:', lines);
      return lines.includes(key);
    } catch (err) {
      console.error('Error reading gist:', err);
      return false;
    }
  }

  // Verify HMAC over {"key":"..."}
  function verifyHmacSignature(payloadObj, signatureHex) {
    try {
      const payloadJson = JSON.stringify(payloadObj);
      const hmacObj = crypto.createHmac('sha256', HMAC_SECRET);
      hmacObj.update(payloadJson);
      const expectedHex = hmacObj.digest('hex');
      // Debug logs:
      // console.log('DEBUG payloadJson:', payloadJson);
      // console.log('DEBUG expectedHex:', expectedHex, 'received:', signatureHex);
      if (signatureHex.length !== expectedHex.length) return false;
      return crypto.timingSafeEqual(Buffer.from(signatureHex,'hex'), Buffer.from(expectedHex,'hex'));
    } catch (err) {
      console.error('HMAC verify error:', err);
      return false;
    }
  }

  if (req.method === 'POST') {
    // Validate license file
    let body;
    try {
      body = await parseJsonBody(req);
    } catch (e) {
      console.error('Failed parse JSON body:', e);
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
    // Verify HMAC
    if (!verifyHmacSignature({ key }, signature)) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
    // Lookup in gist
    const ok = await isKeyValidInGist(key);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(ok ? 'valid' : 'invalid');
  }

  if (req.method === 'GET') {
    // Optionally generate license via GET: curl -o license.lic "https://.../api/validate-key?key=XYZ"
    const key = req.query.key;
    if (!key || typeof key !== 'string') {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(400).send('invalid');
    }
    const ok = await isKeyValidInGist(key);
    if (!ok) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send('invalid');
    }
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
    res.setHeader('Content-Type', 'application/json');
    return res.status(200).send(JSON.stringify(licenseBlob));
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
}

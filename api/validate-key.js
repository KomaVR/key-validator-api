// api/validate-key-simple.js
import fetch from 'node-fetch';

export const config = {
  runtime: 'nodejs', // if using Next.js App Router; otherwise ignore
};

export default async function handler(req, res) {
  const key = req.query.key;
  if (!key) {
    // no key → treat as invalid
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send('invalid');
  }

  const GIST_TOKEN = process.env.GIST_TOKEN;
  const GIST_ID    = process.env.GIST_ID;
  const rawKey     = process.env.RSA_PRIVATE_KEY;
  const PRIV_KEY   = rawKey?.includes("\\n") ? rawKey.replace(/\\n/g, "\n") : rawKey;

  if (!GIST_TOKEN || !GIST_ID || !PRIV_KEY) {
    // misconfigured → optionally log, but return invalid so caller sees “invalid”
    console.error('Server misconfigured: missing env var');
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send('invalid');
  }

  // fetch the gist
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
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send('invalid');
  }
  if (!gistResp.ok) {
    console.error('GitHub API error:', gistResp.status);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send('invalid');
  }

  let gistJson;
  try {
    gistJson = await gistResp.json();
  } catch (err) {
    console.error('Invalid JSON from GitHub:', err);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send('invalid');
  }

  const file = gistJson.files?.['keys.txt'];
  let found = false, redeemed_by = null;
  if (file && typeof file.content === 'string') {
    for (let line of file.content.split('\n')) {
      line = line.trim();
      if (!line || line.startsWith('#')) continue;
      const parts = line.split(',', 4);
      const [k, roleId, by, at] = parts;
      if (k === key) {
        found = true;
        if (by) redeemed_by = by;
        break;
      }
    }
  } else {
    console.warn('keys.txt missing or empty in gist');
  }

  const valid = found && redeemed_by === null;
  res.setHeader('Content-Type', 'text/plain');
  return res.status(200).send(valid ? 'valid' : 'invalid');
}

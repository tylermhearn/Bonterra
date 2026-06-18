## Finding 1

Name
Algorithm confusion from trusting the JWT header

Category
Token forgery

Severity
Critical

The code lets the token choose its own algorithm.
```
const verified = jwt.verify(token, key.n, {
  algorithms: [decoded?.header?.alg],
  issuer: process.env.ISSUER_URL
});
```

An attacker can set alg to HS256 instead of RS256. Because the code passes key.n as the verification key, the verifier may treat public RSA key material as an HMAC secret. The attacker can then forge a token with admin claims.

The fix is to hard code the expected algorithm. Do not trust alg from the JWT header.
```
const verified = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: process.env.ISSUER_URL,
  audience: process.env.API_AUDIENCE
});
```
## Finding 2

Name
Wrong key material passed to jwt.verify

Category
Token forgery

Severity
Critical

The code passes key.n into jwt.verify.

jwt.verify(token, key.n, options);

key.n is only the RSA modulus. It is not a complete RSA public key. This makes verification unsafe, especially when combined with the algorithm confusion issue.

The fix is to convert the full JWK into a real public key before verifying. Use kty, n, and e, or use a vetted JWKS library.
```
const { createPublicKey } = require('crypto');
function jwkToPublicKey(jwk) {
  if (jwk.kty !== 'RSA') {
    throw new Error('invalid key type');
  }
  return createPublicKey({
    key: jwk,
    format: 'jwk'
  });
}
const publicKey = jwkToPublicKey(key);
const verified = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: process.env.ISSUER_URL,
  audience: process.env.API_AUDIENCE
});
```
## Finding 3

Name
Missing audience validation

Category
Authorization bypass

Severity
High

The code checks the issuer but not the audience.
```
const verified = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: process.env.ISSUER_URL
});
```
That means a valid token from the same issuer may work even if it was issued for another API or client. An attacker could get a token for a different service and use it against this document API.

The fix is to require the exact audience for this API.
```
const verified = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: process.env.ISSUER_URL,
  audience: process.env.API_AUDIENCE
});
```
## Finding 4

Name
ID tokens may be accepted as access tokens

Category
Authorization bypass

Severity
High

The middleware does not check that the token is an access token. With no audience check and no token type check, an ID token from the same issuer could be accepted by the API.

The risky code is that it verifies only issuer.
```
const verified = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: process.env.ISSUER_URL
});
```
The fix is to check the expected audience and the provider’s access token marker if one exists. The exact claim depends on the identity provider. For example, some providers use token_use.
```
const verified = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  issuer: process.env.ISSUER_URL,
  audience: process.env.API_AUDIENCE
});
if (verified.token_use && verified.token_use !== 'access') {
  return res.status(401).json({ error: 'unauthorized' });
}
```
If your issuer uses typ, azp, scp, or another claim to distinguish access tokens, enforce that instead.

## Finding 5

Name
JWKS cached forever

Category
Authorization bypass after key compromise

Severity
High

The JWKS is fetched once and never refreshed.
```
let cachedJwks = null;
async function getSigningKey(kid) {
  if (!cachedJwks) {
    const res = await axios.get(process.env.JWKS_URI);
    cachedJwks = res.data.keys;
  }
  return cachedJwks.find(k => k.kid === kid);
}
```
If the identity provider rotates out a compromised key, this API may still trust the old key until the process restarts. An attacker with the old private key could keep minting tokens that this API accepts.

The fix is to add a TTL and refresh keys after that TTL expires. Respecting HTTP cache headers is better, but a short fixed TTL is still much safer than caching forever.
```
let cachedJwks = null;
let jwksFetchedAt = 0;
const JWKS_TTL_MS = 5 * 60 * 1000;
async function fetchJwks() {
  const res = await axios.get(process.env.JWKS_URI, {
    timeout: 2000
  });
  cachedJwks = res.data.keys;
  jwksFetchedAt = Date.now();
}
async function getSigningKey(kid) {
  const expired = Date.now() - jwksFetchedAt > JWKS_TTL_MS;
  if (!cachedJwks || expired) {
    await fetchJwks();
  }
  return cachedJwks.find(k => k.kid === kid);
}
```
## Finding 6

Name
JWKS leaked in the error response

Category
Information disclosure

Severity
Medium, but higher because of the key handling bug

When the kid is unknown, the API returns the entire cached key set.
```
return res.status(401).json({
  error: "unknown key",
  kid: decoded?.header?.kid,
  cachedKeys: cachedJwks
});
```
Public keys are not usually secret. But this code misuses key.n, so leaking the JWKS helps an attacker build a token forgery attempt. It also leaks key IDs and rotation state.

The fix is to return a generic authentication error. Log details only on the server.
```
if (!key) {
  console.warn('JWT rejected because kid was not found', {
    kid: decoded?.header?.kid
  });
  return res.status(401).json({ error: 'unauthorized' });
}
```
## Finding 7

Name
Role claim type confusion

Category
Authorization bypass

Severity
High if role claims can be influenced

The role check assumes the roles claim is an array.
```
const roles = req.user?.['https://example.com/roles'] || [];
if (roles.includes(role)) {
  next();
} else {
  res.sendStatus(403);
}
```
If the claim is a string, .includes() still works. That turns the check into a substring match. A value like "not-admin" could pass a check for "admin".

The fix is to require an array and then check exact role values.
```
const requireRole = (role) => (req, res, next) => {
  const roles = req.user?.['https://example.com/roles'];
  if (!Array.isArray(roles)) {
    return res.sendStatus(403);
  }
  if (!roles.some(r => r === role)) {
    return res.sendStatus(403);
  }
  next();
};
```
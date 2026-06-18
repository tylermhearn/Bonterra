# Bonterra OAuth2 Take-Home

OAuth2 and API security take-home assessment implementation.

## Development

Install dependencies:

```bash
npm install
```

Run the test suite:

```bash
npm test
```

Run TypeScript checks:

```bash
npm run typecheck
```

Build the TypeScript project:

```bash
npm run build
```

## Part 1: JWT Validation Library

The Part 1 module exports a single async validator from `src/index.ts`:

```ts
import { validateToken } from "./src/index.js";

const payload = await validateToken(token, {
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  issuer: "https://auth.example.com/",
  audience: "https://api.example.com",
  clockSkewSeconds: 30,
  jwksCacheTtlSeconds: 300
});
```

`validateToken` returns the decoded payload only after every validation step succeeds. Any failure throws an error with a stable validation error name.

### Options

- `jwksUri`: JWKS endpoint used to fetch public signing keys.
- `issuer`: exact expected `iss` claim.
- `audience`: expected `aud` claim. String and string-array audiences are supported.
- `clockSkewSeconds`: optional clock skew for `exp` and `nbf`; defaults to `30`.
- `jwksCacheTtlSeconds`: optional in-memory JWKS cache TTL; defaults to `300`.

### Validation Order

The implementation validates tokens in this order:

1. Token is well-formed with three base64url segments.
2. Header `alg` is in the positive allowlist. Currently only `RS256` is accepted.
3. Header `kid` resolves to an RSA public key in the JWKS.
4. Signature verifies against the resolved public key.
5. `exp` is still valid with clock skew.
6. Optional `nbf` is not too far in the future with clock skew.
7. `iss` matches exactly.
8. `aud` contains the expected audience.

The algorithm check is intentionally a positive allowlist, not a denylist. Rejecting only `alg: none` leaves the verifier open to downgrade and algorithm-confusion mistakes, including symmetric algorithms such as `HS256`.

### Error Types

- `MalformedTokenError`
- `UnsupportedAlgorithmError`
- `UnknownKeyError`
- `InvalidSignatureError`
- `TokenExpiredError`
- `TokenNotYetValidError`
- `IssuerMismatchError`
- `AudienceMismatchError`
- `JwksFetchError`

These error names are stable enough for later API middleware to return a typed `invalid_token` reason without exposing raw stack traces or internal exception messages.

### JWKS Cache Behavior

JWKS responses are cached in memory per `jwksUri`. The default TTL is 5 minutes (`300` seconds), which balances key rotation responsiveness against avoiding a network request on every API call.

Cache behavior:

- First request for a `jwksUri`: fetch JWKS and cache usable RS256 signing keys.
- Same `kid` within TTL: use the cached key without an HTTP request.
- Unknown `kid` with a fresh cache: refetch once to allow normal key rotation, then throw `UnknownKeyError` if the key is still missing. Repeated unknown-`kid` misses are cooldown-limited so an attacker cannot force a JWKS fetch on every request.
- Expired cache: fetch JWKS again before resolving the key.
- Fetch failure or malformed JWKS: throw `JwksFetchError`.

The validator never falls back to accepting a token when JWKS fetch or parsing fails. Failing closed is the only safe behavior because an unavailable key source cannot prove that a token is authentic.

### Test Coverage

The tests mock `fetch`; no test makes a real HTTP request. Coverage includes:

- Every validation-chain error category.
- JWKS cache hit, TTL expiry, and unknown-`kid` refetch.
- Valid RS256 signature verification.
- Invalid signature and tampered payload rejection.
- HS256 rejection even when JWKS contains only RS256 keys.
- String and array audience handling.

## Part 2: Authorization Middleware

`src/app.ts` implements the authorization layer for the document API using the Part 1 validator.
It intentionally uses in-memory stub document records instead of a database so the exercise stays focused on authentication and authorization behavior.

Middleware:

- `requireAuth(options)`: validates a strict `Authorization: Bearer <token>` header and attaches the decoded payload to `req.auth`.
- `requireScopes(...scopes)`: requires every listed scope to be present in the space-delimited `scope` claim.
- `requireRole(role)`: requires the namespaced `https://example.com/roles` claim to contain the requested role.

Routes:

- `GET /api/documents`: returns only the authenticated user's documents.
- `GET /api/documents/:id`: allows the owner or an auditor.
- `POST /api/documents`: requires `documents:write`.
- `DELETE /api/documents/:id`: allows the owner only; auditors cannot delete.

Ownership checks happen inside route handlers because ownership is resource-specific. The handler has access to the loaded document and can compare its `ownerSub` with `req.auth.sub`; generic middleware should not guess how each route models ownership or load route-specific data. That keeps the reusable middleware limited to token validation, scopes, and roles, while the route stays responsible for resource-aware authorization decisions.

Authentication failures return stable error bodies:

- Missing token: `{ "error": "missing_token" }`
- Invalid token: `{ "error": "invalid_token", "reason": "<typed error name>" }`
- Missing scope: `{ "error": "insufficient_scope" }`
- Missing role: `{ "error": "insufficient_role" }`
- Not owner: `{ "error": "forbidden" }`

The invalid-token response exposes only the typed Part 1 error name, not raw exception messages or stack traces. That gives clients enough information to react while avoiding disclosure of parser internals, key IDs beyond the request context, or infrastructure details.

Part 2 tests cover:

- strict missing-token and invalid-token responses
- scope and role middleware failures
- owner-only listing and deletion behavior
- auditor read access without auditor delete access
- route-handler ownership enforcement instead of middleware-owned resource checks

## Submission Notes

This repository currently contains all four submission artifacts:

- `src/index.ts` for Part 1
- `src/app.ts` for Part 2
- `RESPONSES.md` for Part 3
- `REVIEW.md` for Part 4

No secrets or private keys should be committed. Test keys are generated at runtime.

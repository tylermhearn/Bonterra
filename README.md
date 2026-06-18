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

`validateToken` returns the decoded payload only after every validation step succeeds. Any failure throws a typed error class.

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
- Unknown `kid` with a fresh cache: refetch once to allow normal key rotation, then throw `UnknownKeyError` if the key is still missing.
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

## Submission Notes

This repository currently contains Part 1. Later parts should add:

- Express authorization middleware and document routes.
- `RESPONSES.md` for written OAuth2/security answers.
- `REVIEW.md` for the vulnerability review.

No secrets or private keys should be committed. Test keys are generated at runtime.

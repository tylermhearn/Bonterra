# Part 3 Written Responses

## Question 01

I would not call this a critical issue by itself.

In an Authorization Code flow with PKCE, the main thing is whether the authorization code is tied to the original request. The authorization server should remember the redirect URI, client ID, and PKCE challenge from the first request. Then, during the token exchange, it should require the same redirect URI and the matching code verifier.

So the tester is right that the redirect URI should be checked during the exchange. But whether this is actually exploitable depends on the rest of the system. If the authorization server already checks the redirect URI and PKCE is handled correctly, then the backend not doing its own extra check is probably not critical.

It becomes a real issue if the backend accepts a redirect URI from the client, the authorization server does not check it, and an attacker can get or inject a valid authorization code. In a PKCE flow, the attacker would also need the matching code verifier unless the backend handles that incorrectly too.

I would still fix it. The backend should not trust a redirect URI sent by the mobile client during token exchange. It should use the exact redirect URI from the original authorization request, or reject the request if it does not match. I would also confirm that the authorization server enforces the same rule, because that is what RFC 6749 expects.

## Question 02

Yes, this can be exploited, but the main risk is denial of service, not token forgery.

The attacker sends many fake JWTs with random kid values. Each time the API sees an unknown kid, it re-fetches the JWKS. The attacker still cannot create a valid RS256 signature, so they should not be able to log in as anyone. But they can cause repeated network calls, slow down requests, consume connection pools, and put load on the identity provider.

The fix is to make JWKS refresh controlled. The API should only fetch keys from a trusted, pinned JWKS URL. It should rate limit refreshes, cache unknown kid misses for a short time, use timeouts, and avoid blocking every request on a fresh JWKS fetch.

If the API recently refreshed the JWKS and still does not recognize the kid, the token should fail. It should not trigger another fetch every time.

## Question 03

Service A should not accept a token that was issued for Service B.

The audience claim exists to limit where a token can be used. If a token says it is for Service B, then Service A should reject it. Otherwise, a token with authority meant for one service now works against another service. That breaks the OAuth2 security model.

It also increases the damage from a leaked token. If a Service B token ends up in logs, storage, or a compromised client, the attacker can now use it against Service A too. That should not be possible unless the authorization server issued a token for Service A.

The right pattern is token exchange, sometimes called an on behalf of flow. Service B can take the user token to a trusted authorization server and ask for a new token for Service A. That new token should have Service A as the audience, with the right permissions for Service A.

This keeps delegation clean. The user does not need to authorize every internal service directly, but each service still receives a token meant for that service.

## Question 04

A five minute access token is better from a security point of view. If it gets stolen, the attacker has less time to use it. Account deactivation, permission changes, and revocation take effect faster if the system mostly relies on token expiry.

The downside is reliability. The client has to refresh more often. That means more traffic to the token endpoint and more chances for failure. On mobile, this can be painful when the user has poor connectivity or the app resumes after being offline.

A sixty minute access token is easier for the client. It reduces refresh traffic and works better with spotty mobile connections. But the security tradeoff is real. A stolen token works for much longer. If a user is deactivated or loses access, the old token may still work for up to an hour unless the API does extra server side checks.

I would usually choose something in the middle, like ten to fifteen minutes, with rotating opaque refresh tokens. Between five and sixty minutes, I would choose five minutes for sensitive APIs or bearer tokens that are not sender constrained. I would only choose sixty minutes for lower risk APIs, strong device binding, or mobile use cases where offline reliability matters more than fast revocation.

## Question 05

A JWT can be valid but still not be enough to allow access. If the user deactivated their account at 2 PM, the API should not allow access just because the token does not expire until 2:45 PM.

Short token lifetime helps, but it only limits the window. It does not stop the user during the remaining forty five minutes.

A token denylist can stop a specific access token before it expires. This usually depends on a jti claim. The API checks whether that token ID has been revoked. This works, but it requires a lookup on requests and can be harder if the system does not track every active access token.

A better general approach is a user or session version check. The token includes a session ID, version, or authorization time. The API compares that value to current user or session state in a cache or database. When the account is deactivated, the user is marked inactive or the session version changes. Old tokens then fail even if the signature and expiry are still valid.

Refresh tokens should also be revoked when the account is deactivated. That prevents new access tokens from being issued. But it does not stop an access token that already exists.

For a system with 50,000 active users, I would use short lived access tokens plus a cached account status or session version check in the API middleware. On deactivation, mark the user inactive, revoke refresh tokens, invalidate the session version, and clear related cache entries. That gives fast enforcement without making every JWT fully stateful.

## Question 06

The first reviewer is right if the refresh tokens are high entropy random opaque tokens.

Refresh tokens should be generated with strong randomness. If they are random enough, then storing a SHA 256 hash is fine. If the database is stolen, the attacker only gets hashes. They cannot realistically guess the original token.

bcrypt and Argon2 are meant for passwords because passwords are low entropy and guessable. They help slow down offline guessing. That does not add much value for a 128 bit or 256 bit random token. If the refresh tokens are short, predictable, or user derived, then the token design is the problem. bcrypt or Argon2 would not be the right fix.

## Question 07

I would not use OAuth2 scopes as the main way to represent tenant access.

Scopes are good for API permissions, like reading cases or writing notes. They are not a great fit for tenant membership. A scope like tenant acme read mixes authorization data into the token. It can become hard to revoke quickly, hard to audit cleanly, and large if a user belongs to many tenants.

A custom JWT claim is better if it represents the active tenant for the current session or request. For example, the token could include an active tenant ID. That makes logs easier to understand and avoids putting every tenant membership into the token. But it can still become stale until the token expires unless the API checks current membership.

Keeping tenant authorization in the application layer gives the strongest isolation. The API validates the user identity from the token, then checks the current tenant membership and role in the database or authorization cache. This gives better revocation, better audit records, and avoids large tokens. The tradeoff is that the application needs strong authorization middleware and careful tenant scoped data access.

My recommendation is a hybird. Put the user identity in the token. Include an active tenant ID if it helps route or audit the request. But make the application and database the source of truth for tenant membership, roles, and record access. I would only revisit that if the product later needed third party delegated access, or if every token was centrally introspected on each request.

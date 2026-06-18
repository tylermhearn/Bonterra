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


import { generateKeyPairSync, type JsonWebKey } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  InvalidSignatureError,
  JwksFetchError,
  UnknownKeyError,
  validateToken,
  type ValidateTokenOptions
} from "../src/index.js";

describe("validateToken JWKS cache", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("fetches JWKS on first request and caches the matching kid", async () => {
    const key = rsaJwk("key-1");
    const fetchMock = stubFetch(jwksResponse({ keys: [key] }));
    const token = makeToken("key-1");
    const options = optionsFor("first-request");

    await expect(validateToken(token, options)).rejects.toBeInstanceOf(
      InvalidSignatureError
    );
    await expect(validateToken(token, options)).rejects.toBeInstanceOf(
      InvalidSignatureError
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(options.jwksUri);
  });

  it("refetches JWKS after the TTL expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const key = rsaJwk("key-1");
    const fetchMock = stubFetch(
      jwksResponse({ keys: [key] }),
      jwksResponse({ keys: [key] })
    );
    const token = makeToken("key-1");
    const options = optionsFor("ttl-expiry", { jwksCacheTtlSeconds: 60 });

    await expect(validateToken(token, options)).rejects.toBeInstanceOf(
      InvalidSignatureError
    );

    vi.setSystemTime(new Date("2026-01-01T00:01:01Z"));

    await expect(validateToken(token, options)).rejects.toBeInstanceOf(
      InvalidSignatureError
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("refetches once when a cached JWKS does not contain the token kid", async () => {
    const staleKey = rsaJwk("stale-key");
    const rotatedKey = rsaJwk("rotated-key");
    const fetchMock = stubFetch(
      jwksResponse({ keys: [staleKey] }),
      jwksResponse({ keys: [staleKey, rotatedKey] })
    );
    const options = optionsFor("unknown-kid-triggers-refetch");

    await expect(validateToken(makeToken("stale-key"), options)).rejects.toBeInstanceOf(
      InvalidSignatureError
    );
    await expect(
      validateToken(makeToken("rotated-key"), options)
    ).rejects.toBeInstanceOf(InvalidSignatureError);

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("throws UnknownKeyError after refetch when kid is still unknown", async () => {
    const key = rsaJwk("key-1");
    const fetchMock = stubFetch(
      jwksResponse({ keys: [key] }),
      jwksResponse({ keys: [key] })
    );
    const options = optionsFor("unknown-after-refetch");

    await expect(validateToken(makeToken("key-1"), options)).rejects.toBeInstanceOf(
      InvalidSignatureError
    );
    await expect(
      validateToken(makeToken("missing-key"), options)
    ).rejects.toBeInstanceOf(UnknownKeyError);

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("throws UnknownKeyError when kid is missing", async () => {
    const fetchMock = stubFetch(jwksResponse({ keys: [rsaJwk("key-1")] }));
    const token = makeToken(undefined);

    await expect(validateToken(token, optionsFor("missing-kid"))).rejects.toBeInstanceOf(
      UnknownKeyError
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws JwksFetchError when the JWKS endpoint is unreachable", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("connection refused"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      validateToken(makeToken("key-1"), optionsFor("unreachable"))
    ).rejects.toBeInstanceOf(JwksFetchError);
  });

  it("throws JwksFetchError when the JWKS endpoint returns non-2xx", async () => {
    stubFetch(jwksResponse({ error: "not found" }, 404));

    await expect(
      validateToken(makeToken("key-1"), optionsFor("not-found"))
    ).rejects.toBeInstanceOf(JwksFetchError);
  });

  it("ignores symmetric keys when resolving RS256 kids", async () => {
    stubFetch(
      jwksResponse({
        keys: [{ kty: "oct", kid: "symmetric-key", alg: "HS256", k: "secret" }]
      })
    );

    await expect(
      validateToken(makeToken("symmetric-key"), optionsFor("symmetric-key"))
    ).rejects.toBeInstanceOf(UnknownKeyError);
  });
});

function makeToken(kid: string | undefined): string {
  const header =
    kid === undefined ? { alg: "RS256" } : { alg: "RS256", kid };
  const payload = { sub: "user_123" };

  return `${encodeJson(header)}.${encodeJson(payload)}.${encodeText("signature")}`;
}

function rsaJwk(kid: string): JsonWebKey {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

  return {
    ...publicKey.export({ format: "jwk" }),
    alg: "RS256",
    kid,
    use: "sig"
  };
}

function stubFetch(...responses: Response[]): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn();

  for (const response of responses) {
    fetchMock.mockResolvedValueOnce(response);
  }

  vi.stubGlobal("fetch", fetchMock);

  return fetchMock;
}

function jwksResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
    status
  });
}

function optionsFor(
  testName: string,
  overrides: Partial<ValidateTokenOptions> = {}
): ValidateTokenOptions {
  return {
    jwksUri: `https://auth.example.com/${testName}/.well-known/jwks.json`,
    issuer: "https://auth.example.com/",
    audience: "https://api.example.com",
    ...overrides
  };
}

function encodeJson(value: unknown): string {
  return encodeText(JSON.stringify(value));
}

function encodeText(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

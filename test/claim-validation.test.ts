import {
  createSign,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AudienceMismatchError,
  IssuerMismatchError,
  TokenExpiredError,
  TokenNotYetValidError,
  validateToken,
  type ValidateTokenOptions
} from "../src/index.js";

const ISSUER = "https://auth.example.com/";
const AUDIENCE = "https://api.example.com";

describe("validateToken claim validation", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("accepts a valid token with a string audience", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("valid-string-audience");
    const payload = validPayload();
    const token = context.sign(payload);
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(validateToken(token, optionsFor("valid-string"))).resolves.toEqual(
      payload
    );
  });

  it("accepts a valid token with an audience array containing the expected audience", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("valid-array-audience");
    const payload = validPayload({
      aud: ["https://other-api.example.com", AUDIENCE]
    });
    const token = context.sign(payload);
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(validateToken(token, optionsFor("valid-array"))).resolves.toEqual(
      payload
    );
  });

  it("throws TokenExpiredError when exp is outside the allowed clock skew", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("expired");
    const token = context.sign(validPayload({ exp: epochSeconds() - 31 }));
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(
      validateToken(token, optionsFor("expired"))
    ).rejects.toBeInstanceOf(TokenExpiredError);
  });

  it("accepts exp within the configured clock skew", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("exp-skew");
    const payload = validPayload({ exp: epochSeconds() - 30 });
    const token = context.sign(payload);
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(validateToken(token, optionsFor("exp-skew"))).resolves.toEqual(
      payload
    );
  });

  it("throws TokenNotYetValidError when nbf is too far in the future", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("nbf-future");
    const token = context.sign(validPayload({ nbf: epochSeconds() + 31 }));
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(
      validateToken(token, optionsFor("nbf-future"))
    ).rejects.toBeInstanceOf(TokenNotYetValidError);
  });

  it("accepts nbf within the configured clock skew", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("nbf-skew");
    const payload = validPayload({ nbf: epochSeconds() + 30 });
    const token = context.sign(payload);
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(validateToken(token, optionsFor("nbf-skew"))).resolves.toEqual(
      payload
    );
  });

  it("throws IssuerMismatchError when iss does not match exactly", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("issuer-mismatch");
    const token = context.sign(validPayload({ iss: "https://evil.example.com/" }));
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(
      validateToken(token, optionsFor("issuer-mismatch"))
    ).rejects.toBeInstanceOf(IssuerMismatchError);
  });

  it("throws AudienceMismatchError when aud string does not match", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("audience-string-mismatch");
    const token = context.sign(validPayload({ aud: "https://other-api.example.com" }));
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(
      validateToken(token, optionsFor("audience-string-mismatch"))
    ).rejects.toBeInstanceOf(AudienceMismatchError);
  });

  it("throws AudienceMismatchError when aud array does not contain the expected audience", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("audience-array-mismatch");
    const token = context.sign(
      validPayload({ aud: ["https://other-api.example.com"] })
    );
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(
      validateToken(token, optionsFor("audience-array-mismatch"))
    ).rejects.toBeInstanceOf(AudienceMismatchError);
  });

  it("checks exp before nbf, issuer, and audience", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

    const context = tokenContext("claim-order");
    const token = context.sign(
      validPayload({
        exp: epochSeconds() - 31,
        nbf: epochSeconds() + 31,
        iss: "https://evil.example.com/",
        aud: "https://other-api.example.com"
      })
    );
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await expect(
      validateToken(token, optionsFor("claim-order"))
    ).rejects.toBeInstanceOf(TokenExpiredError);
  });
});

interface TokenContext {
  publicJwk: JsonWebKey;
  sign: (payload: Record<string, unknown>) => string;
}

function tokenContext(kid: string): TokenContext {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048
  });

  return {
    publicJwk: {
      ...publicKey.export({ format: "jwk" }),
      alg: "RS256",
      kid,
      use: "sig"
    },
    sign: (payload: Record<string, unknown>) => signToken(privateKey, kid, payload)
  };
}

function validPayload(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    sub: "user_123",
    iss: ISSUER,
    aud: AUDIENCE,
    exp: epochSeconds() + 300,
    ...overrides
  };
}

function signToken(
  privateKey: KeyObject,
  kid: string,
  payload: Record<string, unknown>
): string {
  const headerSegment = encodeJson({ alg: "RS256", kid });
  const payloadSegment = encodeJson(payload);
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const signer = createSign("RSA-SHA256");

  signer.update(signingInput, "utf8");
  signer.end();

  return `${signingInput}.${signer.sign(privateKey).toString("base64url")}`;
}

function stubFetch(response: Response): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn().mockResolvedValue(response);
  vi.stubGlobal("fetch", fetchMock);

  return fetchMock;
}

function jwksResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" }
  });
}

function optionsFor(testName: string): ValidateTokenOptions {
  return {
    jwksUri: `https://auth.example.com/${testName}/.well-known/jwks.json`,
    issuer: ISSUER,
    audience: AUDIENCE
  };
}

function epochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

import { createHmac, generateKeyPairSync, type JsonWebKey } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  JwksFetchError,
  UnsupportedAlgorithmError,
  validateToken,
  type ValidateTokenOptions
} from "../src/index.js";

describe("validateToken security coverage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("rejects an HS256 token even when the JWKS contains only RS256 keys", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jwksResponse({
        keys: [rsaJwk("rs256-key")]
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      validateToken(hs256Token("rs256-key"), optionsFor("hs256-rejected"))
    ).rejects.toBeInstanceOf(UnsupportedAlgorithmError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws JwksFetchError when the JWKS response is not valid JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("not-json", {
          headers: { "content-type": "application/json" }
        })
      )
    );

    await expect(
      validateToken(unsignedRs256Token("key-1"), optionsFor("bad-json"))
    ).rejects.toBeInstanceOf(JwksFetchError);
  });

  it("throws JwksFetchError when the JWKS response does not contain a keys array", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jwksResponse({ keys: {} })));

    await expect(
      validateToken(unsignedRs256Token("key-1"), optionsFor("bad-shape"))
    ).rejects.toBeInstanceOf(JwksFetchError);
  });

  it("throws JwksFetchError before fetching when the JWKS cache TTL is invalid", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      validateToken(unsignedRs256Token("key-1"), {
        ...optionsFor("bad-ttl"),
        jwksCacheTtlSeconds: -1
      })
    ).rejects.toBeInstanceOf(JwksFetchError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

function hs256Token(kid: string): string {
  const signingInput = `${encodeJson({ alg: "HS256", kid })}.${encodeJson({
    sub: "user_123"
  })}`;
  const signature = createHmac("sha256", "shared-secret")
    .update(signingInput)
    .digest("base64url");

  return `${signingInput}.${signature}`;
}

function unsignedRs256Token(kid: string): string {
  return `${encodeJson({ alg: "RS256", kid })}.${encodeJson({
    sub: "user_123"
  })}.${encodeText("signature")}`;
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

function jwksResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" }
  });
}

function optionsFor(testName: string): ValidateTokenOptions {
  return {
    jwksUri: `https://auth.example.com/${testName}/.well-known/jwks.json`,
    issuer: "https://auth.example.com/",
    audience: "https://api.example.com"
  };
}

function encodeJson(value: unknown): string {
  return encodeText(JSON.stringify(value));
}

function encodeText(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

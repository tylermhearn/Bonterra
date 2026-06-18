import {
  createSign,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  InvalidSignatureError,
  validateToken,
  type ValidateTokenOptions
} from "../src/index.js";

describe("validateToken RS256 signature verification", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns the decoded payload when the RS256 signature is valid", async () => {
    const keyPair = rsaKeyPair("valid-key");
    const payload = {
      sub: "user_123",
      iss: "https://auth.example.com/",
      aud: "https://api.example.com",
      exp: Math.floor(Date.now() / 1000) + 300
    };
    const token = signToken(keyPair.privateKey, "valid-key", payload);

    stubFetch(jwksResponse({ keys: [keyPair.publicJwk] }));

    await expect(validateToken(token, optionsFor("valid"))).resolves.toEqual(
      payload
    );
  });

  it("throws InvalidSignatureError when the token was signed by a different key", async () => {
    const trustedKeyPair = rsaKeyPair("trusted-key");
    const attackerKeyPair = rsaKeyPair("trusted-key");
    const token = signToken(attackerKeyPair.privateKey, "trusted-key", {
      sub: "user_123"
    });

    stubFetch(jwksResponse({ keys: [trustedKeyPair.publicJwk] }));

    await expect(
      validateToken(token, optionsFor("wrong-key"))
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  it("throws InvalidSignatureError when the payload is tampered after signing", async () => {
    const keyPair = rsaKeyPair("tamper-key");
    const token = signToken(keyPair.privateKey, "tamper-key", {
      sub: "user_123",
      admin: false
    });
    const [headerSegment, , signatureSegment] = token.split(".");
    const tamperedToken = `${headerSegment}.${encodeJson({
      sub: "user_123",
      admin: true
    })}.${signatureSegment}`;

    stubFetch(jwksResponse({ keys: [keyPair.publicJwk] }));

    await expect(
      validateToken(tamperedToken, optionsFor("tampered"))
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });
});

interface TestKeyPair {
  privateKey: KeyObject;
  publicJwk: JsonWebKey;
}

function rsaKeyPair(kid: string): TestKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048
  });

  return {
    privateKey,
    publicJwk: {
      ...publicKey.export({ format: "jwk" }),
      alg: "RS256",
      kid,
      use: "sig"
    }
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
    issuer: "https://auth.example.com/",
    audience: "https://api.example.com"
  };
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

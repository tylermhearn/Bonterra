import { afterEach, describe, expect, it, vi } from "vitest";
import {
  MalformedTokenError,
  UnsupportedAlgorithmError,
  validateToken,
  type ValidateTokenOptions
} from "../src/index.js";

const OPTIONS: ValidateTokenOptions = {
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  issuer: "https://auth.example.com/",
  audience: "https://api.example.com"
};

describe("validateToken parsing and algorithm checks", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws MalformedTokenError when the token does not have three segments", async () => {
    await expect(validateToken("header.payload", OPTIONS)).rejects.toBeInstanceOf(
      MalformedTokenError
    );
  });

  it("throws MalformedTokenError when a segment is not base64url encoded", async () => {
    const token = `not+base64url.${encodeJson({ sub: "user_123" })}.signature`;

    await expect(validateToken(token, OPTIONS)).rejects.toBeInstanceOf(
      MalformedTokenError
    );
  });

  it("throws MalformedTokenError when the header is not valid JSON", async () => {
    const token = `${encodeText("not-json")}.${encodeJson({
      sub: "user_123"
    })}.signature`;

    await expect(validateToken(token, OPTIONS)).rejects.toBeInstanceOf(
      MalformedTokenError
    );
  });

  it("throws MalformedTokenError when the payload is not a JSON object", async () => {
    const token = `${encodeJson({ alg: "RS256", kid: "key-1" })}.${encodeText(
      "[]"
    )}.signature`;

    await expect(validateToken(token, OPTIONS)).rejects.toBeInstanceOf(
      MalformedTokenError
    );
  });

  it("throws UnsupportedAlgorithmError for alg none", async () => {
    const token = makeToken({ alg: "none", kid: "key-1" });

    await expect(validateToken(token, OPTIONS)).rejects.toBeInstanceOf(
      UnsupportedAlgorithmError
    );
  });

  it("throws UnsupportedAlgorithmError for HS256", async () => {
    const token = makeToken({ alg: "HS256", kid: "key-1" });

    await expect(validateToken(token, OPTIONS)).rejects.toBeInstanceOf(
      UnsupportedAlgorithmError
    );
  });

  it("does not fetch JWKS before rejecting an unsupported algorithm", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const token = makeToken({ alg: "ES256", kid: "key-1" });

    await expect(validateToken(token, OPTIONS)).rejects.toBeInstanceOf(
      UnsupportedAlgorithmError
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws UnsupportedAlgorithmError when alg is missing", async () => {
    const token = makeToken({ kid: "key-1" });

    await expect(validateToken(token, OPTIONS)).rejects.toBeInstanceOf(
      UnsupportedAlgorithmError
    );
  });
});

function makeToken(
  header: Record<string, unknown>,
  payload: Record<string, unknown> = { sub: "user_123" }
): string {
  return `${encodeJson(header)}.${encodeJson(payload)}.${encodeText("signature")}`;
}

function encodeJson(value: unknown): string {
  return encodeText(JSON.stringify(value));
}

function encodeText(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

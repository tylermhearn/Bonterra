import {
  createSign,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import express from "express";
import { createApp, requireAuth, requireRole } from "../src/app.js";
import type { ValidateTokenOptions } from "../src/index.js";

const ISSUER = "https://auth.example.com/";
const AUDIENCE = "https://api.example.com";
const ROLES_CLAIM = "https://example.com/roles";

describe("Part 2 authorization layer", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns 401 missing_token when Authorization is absent", async () => {
    const response = await request(createApp(optionsFor("missing")))
      .get("/api/documents")
      .expect(401);

    expect(response.body).toEqual({ error: "missing_token" });
  });

  it("returns 401 invalid_token with typed reason for invalid tokens", async () => {
    const context = authContext("invalid-token");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("invalid-token")))
      .get("/api/documents")
      .set("Authorization", `Bearer ${context.sign({ exp: epochSeconds() - 60 })}`)
      .expect(401);

    expect(response.body).toEqual({
      error: "invalid_token",
      reason: "TokenExpiredError"
    });
  });

  it("returns only the authenticated user's documents", async () => {
    const context = authContext("own-documents");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("own-documents")))
      .get("/api/documents")
      .set("Authorization", `Bearer ${context.sign()}`)
      .expect(200);

    expect(response.body.documents).toEqual([
      { id: "doc_1", ownerSub: "user_abc123", title: "Intake notes" },
      { id: "doc_2", ownerSub: "user_abc123", title: "Care plan" }
    ]);
  });

  it("allows an owner to read a document by id", async () => {
    const context = authContext("owner-read");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("owner-read")))
      .get("/api/documents/doc_1")
      .set("Authorization", `Bearer ${context.sign()}`)
      .expect(200);

    expect(response.body.document.id).toBe("doc_1");
  });

  it("allows an auditor to read another user's document", async () => {
    const context = authContext("auditor-read");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("auditor-read")))
      .get("/api/documents/doc_3")
      .set(
        "Authorization",
        `Bearer ${context.sign({ [ROLES_CLAIM]: ["auditor"] })}`
      )
      .expect(200);

    expect(response.body.document.id).toBe("doc_3");
  });

  it("returns 403 forbidden when a non-owner non-auditor reads another user's document", async () => {
    const context = authContext("not-owner");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("not-owner")))
      .get("/api/documents/doc_3")
      .set("Authorization", `Bearer ${context.sign()}`)
      .expect(403);

    expect(response.body).toEqual({ error: "forbidden" });
  });

  it("creates a document for a user with documents:write scope", async () => {
    const context = authContext("write-scope");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("write-scope")))
      .post("/api/documents")
      .set(
        "Authorization",
        `Bearer ${context.sign({ scope: "documents:read documents:write" })}`
      )
      .send({ title: "New note" })
      .expect(201);

    expect(response.body.document).toMatchObject({
      ownerSub: "user_abc123",
      title: "New note"
    });
  });

  it("returns 403 insufficient_scope when documents:write is absent", async () => {
    const context = authContext("missing-scope");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("missing-scope")))
      .post("/api/documents")
      .set("Authorization", `Bearer ${context.sign({ scope: "documents:read" })}`)
      .send({ title: "New note" })
      .expect(403);

    expect(response.body).toEqual({ error: "insufficient_scope" });
  });

  it("allows an owner to delete their document", async () => {
    const context = authContext("owner-delete");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    await request(createApp(optionsFor("owner-delete")))
      .delete("/api/documents/doc_2")
      .set("Authorization", `Bearer ${context.sign()}`)
      .expect(204);
  });

  it("does not allow an auditor to delete another user's document", async () => {
    const context = authContext("auditor-delete");
    stubFetch(jwksResponse({ keys: [context.publicJwk] }));

    const response = await request(createApp(optionsFor("auditor-delete")))
      .delete("/api/documents/doc_3")
      .set(
        "Authorization",
        `Bearer ${context.sign({ [ROLES_CLAIM]: ["auditor"] })}`
      )
      .expect(403);

    expect(response.body).toEqual({ error: "forbidden" });
  });

  it("returns 403 insufficient_role from requireRole when a role is absent", async () => {
    const context = authContext("missing-role");
    const app = express();

    stubFetch(jwksResponse({ keys: [context.publicJwk] }));
    app.get(
      "/audit-only",
      requireAuth(optionsFor("missing-role")),
      requireRole("auditor"),
      (_req, res) => res.json({ ok: true })
    );

    const response = await request(app)
      .get("/audit-only")
      .set("Authorization", `Bearer ${context.sign()}`)
      .expect(403);

    expect(response.body).toEqual({ error: "insufficient_role" });
  });
});

interface AuthContext {
  publicJwk: JsonWebKey;
  sign: (claims?: Record<string, unknown>) => string;
}

function authContext(kid: string): AuthContext {
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
    sign: (claims: Record<string, unknown> = {}) =>
      signToken(privateKey, kid, {
        sub: "user_abc123",
        iss: ISSUER,
        aud: AUDIENCE,
        exp: epochSeconds() + 300,
        scope: "documents:read",
        ...claims
      })
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

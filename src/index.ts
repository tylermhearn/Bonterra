import {
  createPublicKey,
  createVerify,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";

export interface ValidateTokenOptions {
  jwksUri: string;
  issuer: string;
  audience: string;
  clockSkewSeconds?: number;
  jwksCacheTtlSeconds?: number;
}

export type JwtPayload = Record<string, unknown>;

interface JwtHeader extends Record<string, unknown> {
  alg?: unknown;
  kid?: unknown;
}

interface JwksKey extends Record<string, unknown> {
  alg?: unknown;
  kid?: unknown;
  key_ops?: unknown;
  kty?: unknown;
  use?: unknown;
}

interface CachedJwks {
  fetchedAtMs: number;
  keys: Map<string, KeyObject>;
}

interface ParsedToken {
  header: JwtHeader;
  payload: JwtPayload;
  signature: Buffer;
  signingInput: string;
}

const ALLOWED_ALGORITHMS = new Set(["RS256"]);
const DEFAULT_JWKS_CACHE_TTL_SECONDS = 300;
const jwksCache = new Map<string, CachedJwks>();

export class JwtValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class MalformedTokenError extends JwtValidationError {}
export class UnsupportedAlgorithmError extends JwtValidationError {}
export class UnknownKeyError extends JwtValidationError {}
export class InvalidSignatureError extends JwtValidationError {}
export class TokenExpiredError extends JwtValidationError {}
export class TokenNotYetValidError extends JwtValidationError {}
export class IssuerMismatchError extends JwtValidationError {}
export class AudienceMismatchError extends JwtValidationError {}
export class JwksFetchError extends JwtValidationError {}

/**
 * Validates a JWT and returns the decoded payload.
 * Throws a typed error on any validation failure.
 */
export async function validateToken(
  token: string,
  options: ValidateTokenOptions
): Promise<JwtPayload> {
  const parsedToken = parseToken(token);
  assertSupportedAlgorithm(parsedToken.header);
  const key = await resolveJwksKey(parsedToken.header, options);
  verifySignature(parsedToken, key);

  return parsedToken.payload;
}

function parseToken(token: string): ParsedToken {
  if (typeof token !== "string") {
    throw new MalformedTokenError("Token must be a string");
  }

  const segments = token.split(".");
  if (segments.length !== 3) {
    throw new MalformedTokenError("Token must have exactly three segments");
  }

  const [headerSegment, payloadSegment, signatureSegment] = segments;
  if (headerSegment === "" || payloadSegment === "") {
    throw new MalformedTokenError("Token header and payload are required");
  }

  const header = parseJsonObject<JwtHeader>(headerSegment, "header");
  const payload = parseJsonObject<JwtPayload>(payloadSegment, "payload");
  const signature = decodeBase64UrlSegment(signatureSegment, "signature");

  return {
    header,
    payload,
    signature,
    signingInput: `${headerSegment}.${payloadSegment}`
  };
}

function assertSupportedAlgorithm(header: JwtHeader): void {
  if (typeof header.alg !== "string") {
    throw new UnsupportedAlgorithmError("JWT alg header must be a string");
  }

  // Use a positive allowlist so newly invented, downgraded, or symmetric
  // algorithms cannot slip through just because they are not literally "none".
  if (!ALLOWED_ALGORITHMS.has(header.alg)) {
    throw new UnsupportedAlgorithmError(`Unsupported JWT alg: ${header.alg}`);
  }
}

async function resolveJwksKey(
  header: JwtHeader,
  options: ValidateTokenOptions
): Promise<KeyObject> {
  const kid = getHeaderKid(header);
  const ttlMs = getCacheTtlMs(options);
  const cachedJwks = jwksCache.get(options.jwksUri);

  if (cachedJwks && !isCacheExpired(cachedJwks, ttlMs)) {
    const cachedKey = cachedJwks.keys.get(kid);

    if (cachedKey) {
      return cachedKey;
    }

    const refreshedJwks = await fetchAndCacheJwks(options.jwksUri);
    const refreshedKey = refreshedJwks.keys.get(kid);

    if (refreshedKey) {
      return refreshedKey;
    }

    throw new UnknownKeyError(`No JWKS key found for kid: ${kid}`);
  }

  const fetchedJwks = await fetchAndCacheJwks(options.jwksUri);
  const fetchedKey = fetchedJwks.keys.get(kid);

  if (!fetchedKey) {
    throw new UnknownKeyError(`No JWKS key found for kid: ${kid}`);
  }

  return fetchedKey;
}

function getHeaderKid(header: JwtHeader): string {
  if (typeof header.kid !== "string" || header.kid === "") {
    throw new UnknownKeyError("JWT kid header must be a non-empty string");
  }

  return header.kid;
}

function getCacheTtlMs(options: ValidateTokenOptions): number {
  const ttlSeconds =
    options.jwksCacheTtlSeconds ?? DEFAULT_JWKS_CACHE_TTL_SECONDS;

  if (!Number.isFinite(ttlSeconds) || ttlSeconds < 0) {
    throw new JwksFetchError("JWKS cache TTL must be a non-negative number");
  }

  return ttlSeconds * 1000;
}

function isCacheExpired(cachedJwks: CachedJwks, ttlMs: number): boolean {
  return Date.now() - cachedJwks.fetchedAtMs >= ttlMs;
}

async function fetchAndCacheJwks(jwksUri: string): Promise<CachedJwks> {
  let response: Response;

  try {
    response = await fetch(jwksUri);
  } catch (error) {
    throw new JwksFetchError(
      `Unable to fetch JWKS: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }

  if (!response.ok) {
    throw new JwksFetchError(`JWKS endpoint returned HTTP ${response.status}`);
  }

  let jwks: unknown;

  try {
    jwks = await response.json();
  } catch (error) {
    throw new JwksFetchError(
      `JWKS endpoint did not return JSON: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }

  const cachedJwks = {
    fetchedAtMs: Date.now(),
    keys: parseJwks(jwks)
  };

  jwksCache.set(jwksUri, cachedJwks);

  return cachedJwks;
}

function parseJwks(jwks: unknown): Map<string, KeyObject> {
  if (!isPlainObject(jwks) || !Array.isArray(jwks.keys)) {
    throw new JwksFetchError("JWKS response must contain a keys array");
  }

  const keys = new Map<string, KeyObject>();

  for (const key of jwks.keys) {
    const parsedKey = parseJwksKey(key);

    if (parsedKey) {
      keys.set(parsedKey.kid, parsedKey.keyObject);
    }
  }

  return keys;
}

function parseJwksKey(
  candidate: unknown
): { kid: string; keyObject: KeyObject } | null {
  if (!isPlainObject(candidate)) {
    return null;
  }

  const key = candidate as JwksKey;

  if (!isUsableRs256Jwk(key)) {
    return null;
  }

  try {
    return {
      kid: key.kid,
      keyObject: createPublicKey({ format: "jwk", key: key as JsonWebKey })
    };
  } catch {
    return null;
  }
}

function isUsableRs256Jwk(key: JwksKey): key is JwksKey & { kid: string } {
  if (typeof key.kid !== "string" || key.kid === "") {
    return false;
  }

  if (key.kty !== "RSA") {
    return false;
  }

  if (key.use !== undefined && key.use !== "sig") {
    return false;
  }

  if (key.alg !== undefined && key.alg !== "RS256") {
    return false;
  }

  if (
    key.key_ops !== undefined &&
    (!Array.isArray(key.key_ops) || !key.key_ops.includes("verify"))
  ) {
    return false;
  }

  return true;
}

function verifySignature(parsedToken: ParsedToken, key: KeyObject): void {
  try {
    const verifier = createVerify("RSA-SHA256");
    verifier.update(parsedToken.signingInput, "utf8");
    verifier.end();

    if (!verifier.verify(key, parsedToken.signature)) {
      throw new InvalidSignatureError("JWT signature is invalid");
    }
  } catch (error) {
    if (error instanceof InvalidSignatureError) {
      throw error;
    }

    throw new InvalidSignatureError("JWT signature could not be verified");
  }
}

function parseJsonObject<T extends Record<string, unknown>>(
  segment: string,
  label: string
): T {
  const decoded = decodeBase64UrlSegment(segment, label).toString("utf8");

  try {
    const parsed: unknown = JSON.parse(decoded);

    if (!isPlainObject(parsed)) {
      throw new MalformedTokenError(`Token ${label} must be a JSON object`);
    }

    return parsed as T;
  } catch (error) {
    if (error instanceof MalformedTokenError) {
      throw error;
    }

    throw new MalformedTokenError(`Token ${label} must be valid JSON`);
  }
}

function decodeBase64UrlSegment(segment: string, label: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(segment)) {
    throw new MalformedTokenError(`Token ${label} is not base64url encoded`);
  }

  if (segment.length % 4 === 1) {
    throw new MalformedTokenError(`Token ${label} is not base64url encoded`);
  }

  const paddingLength = (4 - (segment.length % 4)) % 4;
  const padded = `${segment}${"=".repeat(paddingLength)}`;
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");

  try {
    return Buffer.from(base64, "base64");
  } catch {
    throw new MalformedTokenError(`Token ${label} is not base64url encoded`);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

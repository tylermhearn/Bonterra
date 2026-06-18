import {
  createPublicKey,
  createVerify,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";

interface ValidateTokenOptions {
  jwksUri: string;
  issuer: string;
  audience: string;
  clockSkewSeconds?: number;
  jwksCacheTtlSeconds?: number;
}

type JwtPayload = Record<string, unknown>;

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
  lastUnknownKidRefetchAtMs?: number;
}

interface ParsedToken {
  header: JwtHeader;
  payload: JwtPayload;
  signature: Buffer;
  signingInput: string;
}

const ALLOWED_ALGORITHMS = new Set(["RS256"]);
const DEFAULT_CLOCK_SKEW_SECONDS = 30;
const DEFAULT_JWKS_CACHE_TTL_SECONDS = 300;
const UNKNOWN_KID_REFETCH_COOLDOWN_MS = 30_000;
const jwksCache = new Map<string, CachedJwks>();

class JwtValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

class MalformedTokenError extends JwtValidationError {}
class UnsupportedAlgorithmError extends JwtValidationError {}
class UnknownKeyError extends JwtValidationError {}
class InvalidSignatureError extends JwtValidationError {}
class TokenExpiredError extends JwtValidationError {}
class TokenNotYetValidError extends JwtValidationError {}
class IssuerMismatchError extends JwtValidationError {}
class AudienceMismatchError extends JwtValidationError {}
class JwksFetchError extends JwtValidationError {}

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
  validateClaims(parsedToken.payload, options);

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

    if (
      cachedJwks.lastUnknownKidRefetchAtMs !== undefined &&
      Date.now() - cachedJwks.lastUnknownKidRefetchAtMs <
        UNKNOWN_KID_REFETCH_COOLDOWN_MS
    ) {
      throw new UnknownKeyError(`No JWKS key found for kid: ${kid}`);
    }

    const refreshedJwks = await fetchAndCacheJwks(options.jwksUri);
    refreshedJwks.lastUnknownKidRefetchAtMs = Date.now();
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

function validateClaims(
  payload: JwtPayload,
  options: ValidateTokenOptions
): void {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const clockSkewSeconds =
    options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new TokenExpiredError("Clock skew must be a non-negative number");
  }

  validateExpiration(payload.exp, nowSeconds, clockSkewSeconds);
  validateNotBefore(payload.nbf, nowSeconds, clockSkewSeconds);
  validateIssuer(payload.iss, options.issuer);
  validateAudience(payload.aud, options.audience);
}

function validateExpiration(
  exp: unknown,
  nowSeconds: number,
  clockSkewSeconds: number
): void {
  if (typeof exp !== "number" || !Number.isFinite(exp)) {
    throw new TokenExpiredError("JWT exp claim must be a number");
  }

  if (exp < nowSeconds - clockSkewSeconds) {
    throw new TokenExpiredError("JWT is expired");
  }
}

function validateNotBefore(
  nbf: unknown,
  nowSeconds: number,
  clockSkewSeconds: number
): void {
  if (nbf === undefined) {
    return;
  }

  if (typeof nbf !== "number" || !Number.isFinite(nbf)) {
    throw new TokenNotYetValidError("JWT nbf claim must be a number");
  }

  if (nbf > nowSeconds + clockSkewSeconds) {
    throw new TokenNotYetValidError("JWT is not valid yet");
  }
}

function validateIssuer(iss: unknown, expectedIssuer: string): void {
  if (iss !== expectedIssuer) {
    throw new IssuerMismatchError("JWT issuer does not match");
  }
}

function validateAudience(aud: unknown, expectedAudience: string): void {
  if (typeof aud === "string") {
    if (aud !== expectedAudience) {
      throw new AudienceMismatchError("JWT audience does not match");
    }

    return;
  }

  if (Array.isArray(aud) && aud.every((value) => typeof value === "string")) {
    if (!aud.includes(expectedAudience)) {
      throw new AudienceMismatchError("JWT audience does not match");
    }

    return;
  }

  throw new AudienceMismatchError("JWT audience must be a string or string array");
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

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

interface ParsedToken {
  header: JwtHeader;
  payload: JwtPayload;
  signature: Buffer;
  signingInput: string;
}

const ALLOWED_ALGORITHMS = new Set(["RS256"]);

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
  _options: ValidateTokenOptions
): Promise<JwtPayload> {
  const parsedToken = parseToken(token);
  assertSupportedAlgorithm(parsedToken.header);

  throw new UnknownKeyError("JWKS key resolution has not been implemented yet");
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

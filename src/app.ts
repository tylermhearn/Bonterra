import express, {
  type NextFunction,
  type Request,
  type Response
} from "express";
import {
  JwtValidationError,
  validateToken,
  type JwtPayload,
  type ValidateTokenOptions
} from "./index.js";

const ROLES_CLAIM = "https://example.com/roles";

export interface AuthenticatedRequest extends Request {
  auth?: JwtPayload;
}

interface DocumentRecord {
  id: string;
  ownerSub: string;
  title: string;
}

export function createApp(authOptions: ValidateTokenOptions): express.Express {
  const app = express();
  const documents = createStubDocuments();

  app.use(express.json());

  app.get("/api/documents", requireAuth(authOptions), (req, res) => {
    const auth = getAuth(req);

    res.json({
      documents: documents.filter((document) => document.ownerSub === auth.sub)
    });
  });

  app.get("/api/documents/:id", requireAuth(authOptions), (req, res) => {
    const auth = getAuth(req);
    const document = findDocument(documents, getRouteParam(req.params.id));

    if (!document) {
      return res.status(404).json({ error: "not_found" });
    }

    if (document.ownerSub !== auth.sub && !hasRole(auth, "auditor")) {
      return res.status(403).json({ error: "forbidden" });
    }

    return res.json({ document });
  });

  app.post(
    "/api/documents",
    requireAuth(authOptions),
    requireScopes("documents:write"),
    (req, res) => {
      const auth = getAuth(req);
      const document = {
        id: `doc_${documents.length + 1}`,
        ownerSub: auth.sub,
        title: typeof req.body?.title === "string" ? req.body.title : "Untitled"
      };

      documents.push(document);

      res.status(201).json({ document });
    }
  );

  app.delete("/api/documents/:id", requireAuth(authOptions), (req, res) => {
    const auth = getAuth(req);
    const document = findDocument(documents, getRouteParam(req.params.id));

    if (!document) {
      return res.status(404).json({ error: "not_found" });
    }

    if (document.ownerSub !== auth.sub) {
      return res.status(403).json({ error: "forbidden" });
    }

    documents.splice(documents.indexOf(document), 1);

    return res.status(204).send();
  });

  return app;
}

export function requireAuth(options: ValidateTokenOptions) {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const token = parseBearerToken(req.headers.authorization);

    if (!token) {
      res.status(401).json({ error: "missing_token" });
      return;
    }

    try {
      req.auth = await validateToken(token, options);
      next();
    } catch (error) {
      const reason =
        error instanceof JwtValidationError ? error.name : "JwtValidationError";

      res.status(401).json({ error: "invalid_token", reason });
    }
  };
}

export function requireScopes(...scopes: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const auth = getAuth(req);
    const tokenScopes =
      typeof auth.scope === "string" ? auth.scope.split(/\s+/).filter(Boolean) : [];

    if (scopes.every((scope) => tokenScopes.includes(scope))) {
      next();
      return;
    }

    res.status(403).json({ error: "insufficient_scope" });
  };
}

export function requireRole(role: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (hasRole(getAuth(req), role)) {
      next();
      return;
    }

    res.status(403).json({ error: "insufficient_role" });
  };
}

function parseBearerToken(authorization: string | undefined): string | null {
  if (!authorization) {
    return null;
  }

  const match = /^Bearer\s+(.+)$/.exec(authorization);

  return match?.[1] ?? null;
}

function getAuth(req: AuthenticatedRequest): JwtPayload & { sub: string } {
  if (typeof req.auth?.sub !== "string") {
    throw new Error("Authenticated request is missing sub claim");
  }

  return req.auth as JwtPayload & { sub: string };
}

function hasRole(auth: JwtPayload, role: string): boolean {
  const roles = auth[ROLES_CLAIM];

  return Array.isArray(roles) && roles.includes(role);
}

function createStubDocuments(): DocumentRecord[] {
  return [
    { id: "doc_1", ownerSub: "user_abc123", title: "Intake notes" },
    { id: "doc_2", ownerSub: "user_abc123", title: "Care plan" },
    { id: "doc_3", ownerSub: "user_other", title: "Supervisor memo" }
  ];
}

function findDocument(
  documents: DocumentRecord[],
  id: string
): DocumentRecord | undefined {
  return documents.find((document) => document.id === id);
}

function getRouteParam(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] : (value ?? "");
}

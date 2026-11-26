#!/usr/bin/env node
/**
 * HTTP-Start: zentraler MCP-Server im Docker-Container.
 *
 * Jeder Request bringt einen eigenen Token dieses Dienstes mit ("Authorization: Bearer gsc_…").
 * Der Dienst kennt davon nur den SHA-256-Hash aus der Freigabedatei. Erst wenn der Hash dort steht,
 * wird der Request verarbeitet, und zwar mit dem Mandanten und der Property-Whitelist dieses Tokens.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { hostHeaderValidation, originValidation, toNodeHandler } from '@modelcontextprotocol/node';
import { AuditLog } from './audit.ts';
import { bearerToken, FailureLimiter, rateLimitKey } from './auth.ts';
import { Budget } from './budget.ts';
import { flag, loadConfig } from './config.ts';
import { GoogleClients } from './google.ts';
import { createGscServer, SERVER_INFO } from './server.ts';
import { hashToken, TokenStore, type Identity, type Tenant } from './tokens.ts';

export interface HttpOptions {
  store: TokenStore;
  google: GoogleClients;
  audit: AuditLog | undefined;
  /** URL-Prüfungen je Mandant und Tag; eine Instanz für alle Requests */
  inspections: Budget;
  /** Hostnamen, unter denen der Server erreichbar sein darf (Schutz vor DNS-Rebinding). */
  allowedHosts: string[];
  /** true: Client-IP aus X-Forwarded-For lesen (nur hinter einem eigenen Reverse Proxy setzen). */
  trustProxy?: boolean;
  path?: string;
  log?: (message: string) => void;
  /** Maximale Fehlversuche pro IP-Adresse (IPv6: pro /64-Netz) in 5 Minuten (Standard 10). */
  maxAuthFailures?: number;
}

const LOCALHOST = ['localhost', '127.0.0.1', '[::1]'];
const MAX_BODY_BYTES = 1024 * 1024;
const UNAUTHORIZED = 'Gültiger Header "Authorization: Bearer <gsc-Token>" erforderlich.';

type AuthedRequest = IncomingMessage & { auth?: { token: string; clientId: string; scopes: string[]; extra?: Record<string, unknown> } };

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

/** Schlüssel für das Rate-Limit: die Adresse des Clients (IPv6 auf /64 gekürzt). */
function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    // Der letzte Eintrag stammt vom eigenen Proxy; frühere kann der Client frei erfinden.
    const last = rateLimitKey((Array.isArray(forwarded) ? forwarded.join(',') : forwarded)?.split(',').at(-1));
    if (last) return last;
  }
  return rateLimitKey(req.socket.remoteAddress) ?? 'unknown';
}

export function createHttpServer(options: HttpOptions) {
  const path = options.path ?? '/mcp';
  const log = options.log ?? ((message: string) => console.error(message));
  const allowed = [...new Set([...options.allowedHosts, ...LOCALHOST])];
  const validateHost = hostHeaderValidation(allowed);
  const validateOrigin = originValidation(allowed);
  const limiter = new FailureLimiter({ max: options.maxAuthFailures });

  const handler = createMcpHandler(
    (ctx) => {
      const identity = ctx.authInfo?.extra?.identity as Identity | undefined;
      if (!identity) throw new Error('Request ohne geprüften Token.');
      return createGscServer({
        identity,
        tenant: ctx.authInfo?.extra?.tenant as Tenant | undefined,
        google: options.google,
        audit: options.audit,
        inspections: options.inspections,
      });
    },
    { maxRequestBodySize: MAX_BODY_BYTES, onerror: (error) => log(`[gsc-mcp] ${error.message}`) },
  );
  const nodeHandler = toNodeHandler(handler, { maxRequestBodySize: MAX_BODY_BYTES, onerror: (error) => log(`[gsc-mcp] ${error.message}`) });

  async function handle(req: AuthedRequest, res: ServerResponse): Promise<void> {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    // Ein vorgeschaltetes NGINX soll Antworten (auch SSE) nicht puffern, ohne dass man dort etwas einstellen muss
    res.setHeader('X-Accel-Buffering', 'no');
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      sendJson(res, 400, { error: 'Ungültige Anfrage.' });
      return;
    }

    if (url.pathname === '/health' && req.method === 'GET') {
      sendJson(res, 200, { status: 'ok' });
      return;
    }
    if (url.pathname !== path) {
      sendJson(res, 404, { error: 'Nicht gefunden.' });
      return;
    }
    if (!validateHost(req, res) || !validateOrigin(req, res)) return;

    const token = bearerToken(req.headers.authorization);
    if (!token) {
      // Ein Request ohne wohlgeformten Token ist kein Rateversuch. Er zählt nicht fürs Rate-Limit: sonst könnte
      // jede Webseite den Browser eines Nutzers diese Adresse abrufen lassen (<img src=…>) und alle aussperren.
      sendJson(res, 401, { error: UNAUTHORIZED }, { 'WWW-Authenticate': 'Bearer realm="gsc-mcp"' });
      return;
    }

    let snapshot;
    try {
      snapshot = await options.store.current();
    } catch {
      // Fehlerhafte Freigabedatei: niemand kommt herein, bis sie korrigiert ist (Meldung steht im Log)
      sendJson(res, 503, { error: 'Der Server ist gerade nicht richtig konfiguriert. Bitte den Betreiber informieren.' }, { 'Retry-After': '60' });
      return;
    }

    const identity = snapshot.byHash.get(hashToken(token));
    if (!identity) {
      const ip = clientIp(req, options.trustProxy ?? false);
      const blocked = limiter.blockedFor(ip);
      if (blocked > 0) {
        sendJson(res, 429, { error: 'Zu viele fehlgeschlagene Anmeldungen. Bitte später erneut versuchen.' }, { 'Retry-After': String(blocked) });
        return;
      }
      limiter.fail(ip);
      sendJson(res, 401, { error: UNAUTHORIZED }, { 'WWW-Authenticate': 'Bearer realm="gsc-mcp"' });
      return;
    }

    // toNodeHandler reicht req.auth als authInfo an die Server-Factory weiter. Der Token selbst bleibt hier.
    req.auth = { token: identity.tokenId, clientId: `gsc-${identity.tokenId}`, scopes: [], extra: { identity, tenant: snapshot.tenants.get(identity.tenant) } };
    await nodeHandler(req, res);
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      log(`[gsc-mcp] ${error instanceof Error ? error.message : String(error)}`);
      if (!res.headersSent) sendJson(res, 500, { error: 'Interner Fehler.' });
      else res.end();
    });
  });
  // Schutz gegen langsam tröpfelnde Requests
  server.headersTimeout = 15_000;
  server.requestTimeout = 60_000;
  server.maxHeadersCount = 100;

  return { server, close: () => Promise.all([handler.close(), new Promise<void>((resolve) => server.close(() => resolve()))]) };
}

async function main(): Promise<void> {
  const config = loadConfig();
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? '127.0.0.1';
  const allowedHosts = (process.env.MCP_ALLOWED_HOSTS ?? '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  const trustProxy = flag(process.env.MCP_TRUST_PROXY);
  if (!config.auditDir) throw new Error('GSC_AUDIT_DIR fehlt: ohne Audit-Log startet der HTTP-Server nicht.');

  const audit = await AuditLog.open(config.auditDir, { retentionDays: config.auditRetentionDays, maxBytes: config.auditMaxBytes });
  const store = await TokenStore.open(config.configFile, { log: (message) => console.error(message) });
  const google = new GoogleClients({ keyDir: config.keyDir, proxy: config.egressProxy });

  const { server, close } = createHttpServer({
    store,
    google,
    audit,
    inspections: new Budget(config.maxInspectionsPerDay),
    allowedHosts,
    trustProxy,
  });
  server.listen(port, host, () => {
    console.error(`[gsc-mcp] ${SERVER_INFO.version} hört auf http://${host}:${port}/mcp (Audit-Log in ${audit.dir}, Google ${config.egressProxy ? `über ${config.egressProxy}` : 'direkt'})`);
    if (allowedHosts.length === 0) console.error('[gsc-mcp] MCP_ALLOWED_HOSTS ist leer: nur Zugriffe über localhost werden angenommen.');
  });

  const shutdown = () => {
    audit.close();
    void close().finally(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    console.error('[gsc-mcp]', error instanceof Error ? error.message : error);
    process.exit(1);
  });
}

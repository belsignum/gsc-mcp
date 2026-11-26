/**
 * Nachbau von Google-Token-Endpunkt und Search Console API für Tests.
 *
 * Prüft jede JWT-Anmeldung wie Google (Signatur mit dem öffentlichen Schlüssel des Service Accounts, aud, exp)
 * und zeichnet auf, welcher Service Account welchen Scope angefordert hat. Jeder Service Account sieht nur
 * seine eigenen Properties; für fremde antwortet der Nachbau mit 403 wie Google.
 */
import { createPublicKey, createVerify, generateKeyPairSync, randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';

export interface ServiceAccount {
  email: string;
  privateKey: string;
  publicKey: string;
  keyId: string;
  /** Properties, die dieser Service Account in der Search Console sehen darf */
  sites: Record<string, string>;
}

export interface TokenRequest {
  iss: string;
  scope: string;
  aud: string;
  lifetime: number;
}

export interface ApiRequest {
  method: string;
  path: string;
  /** Service Account, dem das mitgeschickte Access Token gehört */
  account: string | undefined;
  body: any;
}

export function makeServiceAccount(email: string, sites: Record<string, string>): ServiceAccount {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    email,
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    keyId: randomBytes(20).toString('hex'),
    sites,
  };
}

/** Schlüsseldatei im Format der Google Cloud Console. */
export function keyJson(account: ServiceAccount): string {
  return JSON.stringify({
    type: 'service_account',
    project_id: 'test-project',
    private_key_id: account.keyId,
    private_key: account.privateKey,
    client_email: account.email,
    client_id: '1',
    token_uri: 'https://oauth2.googleapis.com/token',
  });
}

export async function writeKey(dir: string, tenant: string, account: ServiceAccount): Promise<string> {
  const file = join(dir, `${tenant}.json`);
  await writeFile(file, keyJson(account), { mode: 0o600 });
  return file;
}

function base64urlJson(part: string): any {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

export async function startMockGoogle(accounts: ServiceAccount[]) {
  const tokenRequests: TokenRequest[] = [];
  const apiRequests: ApiRequest[] = [];
  const accessTokens = new Map<string, string>(); // Access Token → E-Mail
  const byEmail = new Map(accounts.map((a) => [a.email, a]));
  /** Für Tests: nächste Antworten der API erzwingen (Status + Body) */
  const forced: Array<{ status: number; body: unknown }> = [];
  let total = 0;
  /** Für Tests: Antworten der API verzögern */
  const control = { delayMs: 0 };

  const server: Server = createServer(async (req, res) => {
    total += 1;
    const url = new URL(req.url ?? '/', 'http://mock');
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const raw = Buffer.concat(chunks).toString('utf8');
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    if (url.pathname === '/token' && req.method === 'POST') {
      const form = new URLSearchParams(raw);
      const assertion = form.get('assertion') ?? '';
      const [h, p, s] = assertion.split('.');
      try {
        const header = base64urlJson(h);
        const payload = base64urlJson(p);
        const account = byEmail.get(payload.iss);
        if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer' || header.alg !== 'RS256' || !account) throw new Error('invalid');
        const verifier = createVerify('RSA-SHA256');
        verifier.update(`${h}.${p}`);
        if (!verifier.verify(createPublicKey(account.publicKey), Buffer.from(s, 'base64url'))) throw new Error('signature');
        if (payload.aud !== 'https://oauth2.googleapis.com/token' || payload.exp - payload.iat > 3600) throw new Error('claims');
        tokenRequests.push({ iss: payload.iss, scope: payload.scope, aud: payload.aud, lifetime: payload.exp - payload.iat });
        const accessToken = `ya29.${randomBytes(12).toString('hex')}`;
        accessTokens.set(accessToken, account.email);
        return send(200, { access_token: accessToken, expires_in: 3599, token_type: 'Bearer' });
      } catch {
        return send(400, { error: 'invalid_grant', error_description: 'Invalid JWT Signature.' });
      }
    }

    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    const email = bearer ? accessTokens.get(bearer) : undefined;
    const body = raw ? JSON.parse(raw) : undefined;
    apiRequests.push({ method: req.method ?? 'GET', path: url.pathname, account: email, body });
    if (!email) return send(401, { error: { code: 401, message: 'Request had invalid authentication credentials.', status: 'UNAUTHENTICATED' } });
    if (control.delayMs) await new Promise((resolve) => setTimeout(resolve, control.delayMs));
    const next = forced.shift();
    if (next) return send(next.status, next.body);
    const account = byEmail.get(email)!;
    const denied = (site: string) =>
      send(403, { error: { code: 403, message: `User does not have sufficient permission for site '${site}'.`, errors: [{ reason: 'forbidden' }], status: 'PERMISSION_DENIED' } });

    if (url.pathname === '/webmasters/v3/sites' && req.method === 'GET') {
      return send(200, { siteEntry: Object.entries(account.sites).map(([siteUrl, permissionLevel]) => ({ siteUrl, permissionLevel })) });
    }
    const site = /^\/webmasters\/v3\/sites\/([^/]+)(\/.*)?$/.exec(url.pathname);
    if (site) {
      const siteUrl = decodeURIComponent(site[1]);
      if (!Object.hasOwn(account.sites, siteUrl)) return denied(siteUrl);
      const rest = site[2] ?? '';
      if (rest === '/searchAnalytics/query' && req.method === 'POST') {
        const dims: string[] = body?.dimensions ?? [];
        const rows = Array.from({ length: Math.min(3, body?.rowLimit ?? 3) }, (_, i) => ({
          keys: dims.map((d) => `${d}-${i}`),
          clicks: 10 - i,
          impressions: 100 + i,
          ctr: (10 - i) / (100 + i),
          position: 1.23456 + i,
        }));
        return send(200, { rows, responseAggregationType: 'byProperty' });
      }
      if (rest === '/sitemaps' && req.method === 'GET') {
        return send(200, { sitemap: [{ path: 'https://www.example.com/sitemap.xml', isPending: false, isSitemapsIndex: false, errors: '0', warnings: '0' }] });
      }
      const sitemap = /^\/sitemaps\/(.+)$/.exec(rest);
      if (sitemap && req.method === 'GET') {
        return send(200, { path: decodeURIComponent(sitemap[1]), isPending: false, errors: '0', warnings: '0' });
      }
      return send(404, { error: { code: 404, message: 'Not found', status: 'NOT_FOUND' } });
    }
    if (url.pathname === '/v1/urlInspection/index:inspect' && req.method === 'POST') {
      if (!Object.hasOwn(account.sites, body?.siteUrl)) return denied(String(body?.siteUrl));
      return send(200, { inspectionResult: { inspectionResultLink: 'https://search.google.com/…', indexStatusResult: { verdict: 'PASS', coverageState: 'Submitted and indexed' } } });
    }
    return send(404, { error: { code: 404, message: 'Not found', status: 'NOT_FOUND' } });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${port}`;

  /** Leitet die echten Google-Adressen an den Nachbau um. Alles andere schlägt fehl. */
  const fetchImplementation: typeof fetch = (input, init) => {
    const target = String(input instanceof Request ? input.url : input);
    let rewritten: string;
    if (target.startsWith('https://oauth2.googleapis.com/token')) rewritten = `${origin}/token`;
    else if (target.startsWith('https://searchconsole.googleapis.com/')) rewritten = origin + target.slice('https://searchconsole.googleapis.com'.length);
    else return Promise.reject(new Error(`Unerwartetes Ziel: ${target}`));
    return fetch(rewritten, init);
  };

  return {
    origin,
    tokenRequests,
    apiRequests,
    forced,
    control,
    fetchImplementation,
    /** Anzahl aller Requests an "Google" (Token-Endpunkt und API, auch abgelehnte) */
    get requestCount() {
      return total;
    },
    reset() {
      tokenRequests.length = 0;
      apiRequests.length = 0;
      total = 0;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

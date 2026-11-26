import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { AuditLog } from '../src/audit.ts';
import { Budget } from '../src/budget.ts';
import { GoogleClients } from '../src/google.ts';
import { createHttpServer, type HttpOptions } from '../src/http.ts';
import { generateToken, generateTokenId, hashToken, TokenStore, writeConfigFile, type ConfigFile } from '../src/tokens.ts';
import { makeServiceAccount, startMockGoogle, writeKey, type ServiceAccount } from './mock-google.ts';

export type ToolResult = Awaited<ReturnType<Client['callTool']>>;

/** Properties der beiden Testmandanten. Nur example-Domains. */
export const A_PROPERTY = 'sc-domain:kunde-a.example';
export const A_PREFIX = 'https://www.kunde-a.example/';
export const A_NOT_SHARED = 'https://blog.kunde-a.example/';
export const B_PROPERTY = 'sc-domain:kunde-b.example';
export const NOWHERE = 'sc-domain:gibt-es-nicht.example';

export interface Fixture {
  dir: string;
  configFile: string;
  keyDir: string;
  auditDir: string;
  accounts: { a: ServiceAccount; b: ServiceAccount };
  tokens: { a: string; a2: string; b: string };
  config: ConfigFile;
  google: Awaited<ReturnType<typeof startMockGoogle>>;
}

/**
 * Zwei Mandanten mit je eigenem Service Account:
 * - kunde-a sieht bei Google A_PROPERTY, A_PREFIX und A_NOT_SHARED; Token a darf A_PROPERTY und A_PREFIX
 *   sowie eine Property, die der Service Account nicht sieht (Google antwortet 403).
 * - kunde-b sieht B_PROPERTY; Token b darf B_PROPERTY.
 */
export async function makeFixture(): Promise<Fixture> {
  const dir = await mkdtemp(join(tmpdir(), 'gsc-mcp-test-'));
  const keyDir = join(dir, 'keys');
  const auditDir = join(dir, 'audit');
  await mkdir(keyDir, { mode: 0o700 });
  const a = makeServiceAccount('gsc-kunde-a@test-project.iam.gserviceaccount.com', {
    [A_PROPERTY]: 'siteRestrictedUser',
    [A_PREFIX]: 'siteRestrictedUser',
    [A_NOT_SHARED]: 'siteRestrictedUser',
  });
  const b = makeServiceAccount('gsc-kunde-b@test-project.iam.gserviceaccount.com', { [B_PROPERTY]: 'siteRestrictedUser' });
  await writeKey(keyDir, 'kunde-a', a);
  await writeKey(keyDir, 'kunde-b', b);
  const tokens = { a: generateToken(), a2: generateToken(), b: generateToken() };
  const config: ConfigFile = {
    version: 1,
    tenants: { 'kunde-a': { service_account: a.email }, 'kunde-b': { service_account: b.email } },
    tokens: [
      { id: generateTokenId(), user: 'anna', tenant: 'kunde-a', properties: [A_PROPERTY, A_PREFIX, 'sc-domain:ohne-zugriff.example'], token_sha256: hashToken(tokens.a) },
      { id: generateTokenId(), user: 'alex', tenant: 'kunde-a', properties: [A_PREFIX], token_sha256: hashToken(tokens.a2) },
      { id: generateTokenId(), user: 'ben', tenant: 'kunde-b', properties: [B_PROPERTY], token_sha256: hashToken(tokens.b) },
    ],
  };
  const configFile = join(dir, 'tokens.yaml');
  await writeConfigFile(configFile, config);
  const google = await startMockGoogle([a, b]);
  return { dir, configFile, keyDir, auditDir, accounts: { a, b }, tokens, config, google };
}

/** Startet den MCP-HTTP-Server gegen den Google-Nachbau. */
export async function startMcp(fixture: Fixture, overrides: Partial<HttpOptions> & { maxInspectionsPerDay?: number; auditMaxBytes?: number } = {}) {
  const { maxInspectionsPerDay = 500, auditMaxBytes, ...options } = overrides;
  const audit = await AuditLog.open(fixture.auditDir, { maxBytes: auditMaxBytes });
  const store = await TokenStore.open(fixture.configFile, { checkIntervalMs: 0 });
  const google = new GoogleClients({ keyDir: fixture.keyDir, fetchImplementation: fixture.google.fetchImplementation, keyCheckIntervalMs: 0 });
  const { server, close } = createHttpServer({ store, google, audit, inspections: new Budget(maxInspectionsPerDay), allowedHosts: [], log: () => {}, ...options });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    close: async () => {
      audit.close();
      await close();
    },
  };
}

export async function cleanup(fixture: Fixture) {
  await fixture.google.close();
  await rm(fixture.dir, { recursive: true, force: true });
}

export async function connect(url: string, token: string) {
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  return client;
}

export function text(result: ToolResult): string {
  const first = (result.content as Array<{ type: string; text?: string }>)[0];
  return first?.text ?? '';
}

export function json(result: ToolResult): any {
  assert.ok(!result.isError, `Tool-Fehler: ${text(result)}`);
  return JSON.parse(text(result));
}

/** Roher JSON-RPC-Aufruf ohne MCP-Client, für Angriffstests. */
export async function rawPost(url: string, options: { token?: string; headers?: Record<string, string>; body?: string } = {}) {
  return fetch(`${url}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...(options.token !== undefined ? { Authorization: `Bearer ${options.token}` } : {}),
      ...options.headers,
    },
    body: options.body ?? JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });
}

/** Tool-Aufruf als roher JSON-RPC-Request; liefert das JSON-RPC-Ergebnis so, wie es über die Leitung kommt. */
export async function rawToolCall(url: string, token: string, name: string, args: Record<string, unknown>): Promise<{ status: number; result: unknown; raw: string }> {
  const response = await rawPost(url, { token, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
  const raw = await response.text();
  const data = raw.startsWith('{') ? raw : (/^data: (.*)$/m.exec(raw)?.[1] ?? raw);
  return { status: response.status, result: JSON.parse(data).result, raw: data };
}

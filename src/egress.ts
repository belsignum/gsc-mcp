#!/usr/bin/env node
/**
 * Egress-Proxy: der einzige Weg des Servers ins Internet.
 *
 * Der Server-Container hängt nur an einem internen Docker-Netz ohne Internetzugang. Für Google benutzt er
 * diesen Proxy (HTTP CONNECT). Der Proxy baut Tunnel nur zu den Zielen der Allowlist auf, Standard:
 * oauth2.googleapis.com:443 und searchconsole.googleapis.com:443. TLS bleibt Ende zu Ende zwischen Server
 * und Google; der Proxy sieht nur Zielname und Datenmenge.
 *
 * Löst ein erlaubter Name auf eine private, lokale oder sonst nicht öffentliche Adresse auf (manipuliertes DNS),
 * wird die Verbindung abgelehnt. Klartext-HTTP über den Proxy gibt es nicht.
 */
import { createServer, type IncomingMessage } from 'node:http';
import { BlockList, connect, isIP, type Socket } from 'node:net';
import { lookup } from 'node:dns/promises';

export const DEFAULT_ALLOW = ['oauth2.googleapis.com:443', 'searchconsole.googleapis.com:443'];

/** Adressbereiche, zu denen der Proxy nie verbindet. */
const BLOCKED = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  BLOCKED.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  BLOCKED.addSubnet(net, prefix, 'ipv6');
}

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !BLOCKED.check(address, 'ipv4');
  if (family === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped) return !BLOCKED.check(mapped[1], 'ipv4');
    return !BLOCKED.check(address, 'ipv6');
  }
  return false;
}

/** Liest die Allowlist ("host:port,host:port"). */
export function parseAllow(value: string | undefined): Set<string> {
  const entries = (value?.trim() ? value.split(',') : DEFAULT_ALLOW).map((entry) => entry.trim().toLowerCase()).filter(Boolean);
  for (const entry of entries) {
    if (!/^[a-z0-9.-]+:\d{1,5}$/.test(entry)) throw new Error(`EGRESS_ALLOW: "${entry}" ist kein Ziel der Form host:port.`);
  }
  return new Set(entries);
}

export interface EgressOptions {
  allow: Set<string>;
  /** Nur für Tests: Namensauflösung ersetzen */
  resolve?: (host: string) => Promise<string[]>;
  /** Nur für Tests: auch nicht öffentliche Adressen erlauben */
  allowPrivate?: boolean;
  log?: (message: string) => void;
  maxConnections?: number;
  connectTimeoutMs?: number;
  idleTimeoutMs?: number;
}

async function defaultResolve(host: string): Promise<string[]> {
  return (await lookup(host, { all: true, order: 'ipv4first' })).map((entry) => entry.address);
}

export function createEgressProxy(options: EgressOptions) {
  const log = options.log ?? ((message: string) => console.error(message));
  const resolve = options.resolve ?? defaultResolve;
  const idle = options.idleTimeoutMs ?? 120_000;

  const server = createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end('{"status":"ok"}');
      return;
    }
    // Kein Klartext-Proxy: nur CONNECT-Tunnel zu den erlaubten Zielen
    res.writeHead(405, { Connection: 'close' }).end();
  });

  server.on('connect', (req: IncomingMessage, client: Socket, head: Buffer) => {
    const deny = (status: string, reason: string) => {
      log(`[egress] abgelehnt: ${String(req.url).slice(0, 200)} (${reason})`);
      client.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    };
    client.on('error', () => client.destroy());
    const target = String(req.url ?? '').toLowerCase();
    const match = /^([a-z0-9.-]+):(\d{1,5})$/.exec(target);
    if (!match || !options.allow.has(target)) return deny('403 Forbidden', 'nicht in der Allowlist');
    const [, host, port] = match;

    resolve(host)
      .then((addresses) => {
        const usable = options.allowPrivate ? addresses : addresses.filter(isPublicAddress);
        if (usable.length === 0) return deny('502 Bad Gateway', addresses.length ? `nicht öffentliche Adresse ${addresses.join(', ')}` : 'Name nicht auflösbar');
        const upstream = connect({ host: usable[0], port: Number(port), timeout: options.connectTimeoutMs ?? 10_000 });
        upstream.once('timeout', () => upstream.destroy(new Error('Zeitüberschreitung')));
        upstream.once('connect', () => {
          upstream.setTimeout(idle);
          client.setTimeout(idle);
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (head.length) upstream.write(head);
          upstream.pipe(client);
          client.pipe(upstream);
        });
        upstream.on('timeout', () => upstream.destroy());
        client.on('timeout', () => client.destroy());
        upstream.on('error', (error) => {
          if (!client.destroyed && upstream.connecting) deny('502 Bad Gateway', `keine Verbindung: ${error.message}`);
          else client.destroy();
        });
        upstream.on('close', () => client.destroy());
        client.on('close', () => upstream.destroy());
      })
      .catch((error: unknown) => deny('502 Bad Gateway', `Name nicht auflösbar: ${error instanceof Error ? error.message : String(error)}`));
  });

  server.maxConnections = options.maxConnections ?? 64;
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  return server;
}

if (import.meta.main) {
  const allow = parseAllow(process.env.EGRESS_ALLOW);
  const port = Number(process.env.EGRESS_PORT ?? 3128);
  const server = createEgressProxy({ allow });
  server.listen(port, process.env.EGRESS_HOST ?? '0.0.0.0', () => {
    console.error(`[egress] hört auf Port ${port}, erlaubt: ${[...allow].join(', ')}`);
  });
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

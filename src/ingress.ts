#!/usr/bin/env node
/**
 * Weiterleitung für den Betrieb hinter einem vorhandenen NGINX (docker-compose.nginx.yml).
 *
 * Der Server-Container hängt nur am internen Docker-Netz, und interne Netze veröffentlichen keine Ports.
 * Dieser Container hängt an beiden Netzen, veröffentlicht 127.0.0.1:<MCP_PORT> und reicht jede TCP-Verbindung
 * unverändert an den Server weiter. Er liest und ändert nichts, auch keine Header: X-Forwarded-For des
 * NGINX kommt so beim Server an, wie das NGINX es schickt.
 */
import { connect, createServer } from 'node:net';

export function createForwarder(target: { host: string; port: number }, options: { maxConnections?: number; idleTimeoutMs?: number; firstByteTimeoutMs?: number } = {}) {
  const idle = options.idleTimeoutMs ?? 120_000;
  const server = createServer((client) => {
    const upstream = connect(target.port, target.host);
    // Wer verbindet und nichts schickt, belegt nur einen Platz: nach 10 s ohne Daten wird getrennt
    client.setTimeout(options.firstByteTimeoutMs ?? 10_000, () => client.destroy());
    client.once('data', () => client.setTimeout(idle));
    upstream.setTimeout(idle, () => upstream.destroy());
    client.on('error', () => upstream.destroy());
    upstream.on('error', () => client.destroy());
    client.on('close', () => upstream.destroy());
    upstream.on('close', () => client.destroy());
    client.pipe(upstream);
    upstream.pipe(client);
  });
  server.maxConnections = options.maxConnections ?? 500;
  return server;
}

if (import.meta.main) {
  const [host, port] = (process.env.INGRESS_TARGET ?? 'gsc-mcp:3000').split(':');
  const listen = Number(process.env.INGRESS_PORT ?? 3001);
  const server = createForwarder({ host, port: Number(port) });
  server.listen(listen, '0.0.0.0', () => console.error(`[ingress] Port ${listen} → ${host}:${port}`));
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

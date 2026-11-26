/**
 * Egress-Proxy und Weiterleitung: nur erlaubte Ziele, keine privaten Adressen, kein Klartext-Proxy.
 * Der Weg Server → Proxy → Google wird mit dem echten HTTP-Client (gaxios mit Proxy-Agent) geprüft.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import { connect, type AddressInfo } from 'node:net';
import { createEgressProxy, isPublicAddress, parseAllow } from '../src/egress.ts';
import { createForwarder } from '../src/ingress.ts';

function listen(server: { listen: (port: number, host: string, cb: () => void) => unknown; address: () => unknown }): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

/** Schickt einen CONNECT an den Proxy und liefert die Statuszeile. */
function connectVia(proxyPort: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(proxyPort, '127.0.0.1', () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk;
      if (data.includes('\r\n')) {
        resolve(data.split('\r\n')[0]);
        socket.destroy();
      }
    });
    socket.on('error', reject);
    socket.on('close', () => resolve(data.split('\r\n')[0]));
  });
}

describe('Egress-Proxy', () => {
  let upstream: Server;
  let upstreamPort: number;
  let proxy: ReturnType<typeof createEgressProxy>;
  let proxyPort: number;
  const denied: string[] = [];

  before(async () => {
    upstream = createServer((_req, res) => res.end('hallo'));
    upstreamPort = await listen(upstream);
    proxy = createEgressProxy({
      allow: parseAllow(`oauth2.googleapis.com:${upstreamPort},searchconsole.googleapis.com:443,intern.example:${upstreamPort}`),
      // Testauflösung: die Google-Namen zeigen auf den lokalen Testserver, intern.example auf eine private Adresse
      resolve: async (host) => (host === 'intern.example' ? ['10.0.0.5'] : ['127.0.0.1']),
      allowPrivate: false,
      log: (message) => denied.push(message),
    });
    proxyPort = await listen(proxy);
  });
  after(async () => {
    await new Promise((resolve) => proxy.close(resolve));
    await new Promise((resolve) => upstream.close(resolve));
  });

  test('Ziele außerhalb der Allowlist: 403, auch andere Ports und Schreibweisen', async () => {
    for (const target of ['example.com:443', 'searchconsole.googleapis.com:80', 'evil.example:443', 'oauth2.googleapis.com.evil.example:443', '127.0.0.1:22', 'searchconsole.googleapis.com:443/x', '[::1]:443']) {
      assert.match(await connectVia(proxyPort, target), /^HTTP\/1\.1 403/, target);
    }
    assert.ok(denied.some((line) => line.includes('evil.example')));
  });

  test('Erlaubter Name, der auf eine nicht öffentliche Adresse zeigt: abgelehnt', async () => {
    // 127.0.0.1 ist nicht öffentlich: auch die erlaubten Namen werden hier abgelehnt (manipuliertes DNS)
    assert.match(await connectVia(proxyPort, `oauth2.googleapis.com:${upstreamPort}`), /^HTTP\/1\.1 502/);
    assert.match(await connectVia(proxyPort, `intern.example:${upstreamPort}`), /^HTTP\/1\.1 502/);
  });

  test('Kein Klartext-Proxy: GET mit absoluter URL wird abgelehnt', async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port: proxyPort, method: 'GET', path: 'http://example.com/' }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(status, 405);
  });

  test('isPublicAddress: nur öffentliche IPv4-Adressen; IPv6 nie (NAT64, 6to4, Teredo können auf alles zeigen)', () => {
    for (const ip of ['10.1.2.3', '172.20.0.1', '192.168.1.1', '127.0.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', 'kein-ip']) {
      assert.equal(isPublicAddress(ip), false, ip);
    }
    for (const ip of ['::1', 'fd00::1', 'fe80::1', '::ffff:10.0.0.1', '64:ff9b::7f00:1', '::7f00:1', '::127.0.0.1', '::ffff:0:7f00:1', '2002:7f00:1::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2', 'fec0::1', '2a00:1450:4001:80b::200a']) {
      assert.equal(isPublicAddress(ip), false, ip);
    }
    assert.equal(isPublicAddress('142.250.185.106'), true);
  });

  test('parseAllow: Standard sind genau die beiden Google-Ziele', () => {
    assert.deepEqual([...parseAllow(undefined)], ['oauth2.googleapis.com:443', 'searchconsole.googleapis.com:443']);
    assert.throws(() => parseAllow('*.googleapis.com'));
  });
});

describe('Egress-Proxy mit dem HTTP-Client des Servers', () => {
  test('gaxios schickt Google-Anfragen per CONNECT über den Proxy; TLS bleibt Ende zu Ende', async () => {
    const { Gaxios } = await import('gaxios');
    const { createServer: createTcpServer } = await import('node:net');
    // Das Ziel spricht kein TLS. Dass der Client daran scheitert, zeigt: der TLS-Handshake läuft durch den
    // Tunnel bis zum Ziel; der Proxy terminiert kein TLS und kann nicht mitlesen.
    let received = '';
    const target = createTcpServer((socket) => {
      socket.once('data', (chunk) => {
        received = chunk.toString('latin1');
        socket.end('HTTP/1.1 200 OK\r\n\r\nkein TLS');
      });
    });
    const targetPort = await listen(target);
    const targets: string[] = [];
    const proxy = createEgressProxy({ allow: parseAllow(`searchconsole.googleapis.com:${targetPort}`), resolve: async () => ['127.0.0.1'], allowPrivate: true, log: () => {} });
    proxy.prependListener('connect', (req) => targets.push(String(req.url)));
    const proxyPort = await listen(proxy);
    try {
      const client = new Gaxios({ proxy: `http://127.0.0.1:${proxyPort}`, maxRedirects: 0, retry: false });
      await assert.rejects(client.request({ url: `https://searchconsole.googleapis.com:${targetPort}/webmasters/v3/sites` }));
      assert.deepEqual(targets, [`searchconsole.googleapis.com:${targetPort}`]);
      // Beim Ziel kam ein TLS-ClientHello an (Record-Typ 0x16), kein Klartext-HTTP
      assert.equal(received.charCodeAt(0), 0x16);
      assert.ok(!received.includes('GET /webmasters'));
    } finally {
      await new Promise((resolve) => proxy.close(resolve));
      await new Promise((resolve) => target.close(resolve));
    }
  });
});

describe('Weiterleitung (NGINX-Variante)', () => {
  test('trennt Verbindungen, die nichts schicken (sonst ließen sich alle Plätze mit leeren Verbindungen belegen)', async () => {
    const target = createServer((_req, res) => res.end('ok'));
    const targetPort = await listen(target);
    const forwarder = createForwarder({ host: '127.0.0.1', port: targetPort }, { firstByteTimeoutMs: 200 });
    const port = await listen(forwarder);
    try {
      const started = Date.now();
      await new Promise<void>((resolve, reject) => {
        const socket = connect(port, '127.0.0.1');
        socket.on('close', () => resolve());
        socket.on('error', () => {});
        setTimeout(() => reject(new Error('Verbindung bleibt offen')), 3000);
      });
      assert.ok(Date.now() - started < 2000);
    } finally {
      await new Promise((resolve) => forwarder.close(resolve));
      await new Promise((resolve) => target.close(resolve));
    }
  });

  test('reicht Bytes unverändert weiter, auch X-Forwarded-For', async () => {
    let seen: string | undefined;
    const target = createServer((req, res) => {
      seen = req.headers['x-forwarded-for'] as string;
      res.end('ok');
    });
    const targetPort = await listen(target);
    const forwarder = createForwarder({ host: '127.0.0.1', port: targetPort });
    const port = await listen(forwarder);
    try {
      const body = await new Promise<string>((resolve, reject) => {
        const req = request({ host: '127.0.0.1', port, path: '/health', agent: false, headers: { 'X-Forwarded-For': '203.0.113.7, 198.51.100.1' } }, (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => resolve(data));
        });
        req.on('error', reject);
        req.end();
      });
      assert.equal(body, 'ok');
      assert.equal(seen, '203.0.113.7, 198.51.100.1');
    } finally {
      await new Promise((resolve) => forwarder.close(resolve));
      await new Promise((resolve) => target.close(resolve));
    }
  });
});

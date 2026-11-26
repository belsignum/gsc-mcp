/**
 * HTTP-Eingang: Healthcheck, Pfade, Host- und Origin-Prüfung, Größenlimit, X-Forwarded-For.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { connect as openSocket } from 'node:net';
import { bearerToken, FailureLimiter, rateLimitKey } from '../src/auth.ts';
import { generateToken } from '../src/tokens.ts';
import { cleanup, makeFixture, rawPost, startMcp, type Fixture } from './helpers.ts';

let fixture: Fixture;
let mcp: Awaited<ReturnType<typeof startMcp>>;

before(async () => {
  fixture = await makeFixture();
  mcp = await startMcp(fixture, { allowedHosts: ['mcp.example.com'], maxAuthFailures: 3 });
});
after(async () => {
  await mcp.close();
  await cleanup(fixture);
});

/** POST mit frei wählbaren Headern (fetch erlaubt z. B. keinen eigenen Host-Header). */
function post(port: number, headers: Record<string, string>, body = '{}'): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path: '/mcp', method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers } }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', reject);
    req.end(body);
  });
}

function rawStatus(port: number, data: string): Promise<number> {
  return new Promise((resolve, reject) => {
    let received = '';
    const socket = openSocket(port, '127.0.0.1', () => socket.write(data));
    socket.on('data', (chunk) => {
      received += chunk;
      const status = /^HTTP\/1\.1 (\d{3})/.exec(received);
      if (status) {
        resolve(Number(status[1]));
        socket.destroy();
      }
    });
    socket.on('error', (error) => (received ? undefined : reject(error)));
  });
}

describe('HTTP-Eingang', () => {
  test('/health verrät nichts', async () => {
    const response = await fetch(`${mcp.url}/health`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: 'ok' });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('access-control-allow-origin'), null);
  });

  test('Andere Pfade: 404; kaputte Pfade: 400 statt 500', async () => {
    for (const path of ['/', '/mcp/', '/admin', '/.env', '/mcp.json']) {
      assert.equal((await fetch(`${mcp.url}${path}`)).status, 404, path);
    }
    assert.equal(await rawStatus(mcp.port, 'GET // HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'), 400);
  });

  test('Fremder Host- oder Origin-Header: 403, auch mit gültigem Token (DNS-Rebinding)', async () => {
    const auth = { Authorization: `Bearer ${fixture.tokens.a}` };
    assert.equal(await post(mcp.port, { ...auth, Host: 'evil.example' }), 403);
    assert.equal(await post(mcp.port, { ...auth, Host: 'mcp.example.com', Origin: 'https://evil.example' }), 403);
    assert.equal(await post(mcp.port, { ...auth, Host: 'mcp.example.com', Origin: 'null' }), 403);
    assert.equal(await post(mcp.port, { ...auth, Host: 'mcp.example.com' }, JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })), 200);
  });

  test('Requests über 1 MB: 413', async () => {
    // Rohe Verbindung: fetch bricht je nach Timing mit EPIPE ab, wenn der Server antwortet, während der Body noch gesendet wird
    const head = `POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${fixture.tokens.a}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n`;
    assert.equal(await rawStatus(mcp.port, `${head}Content-Length: 1100000\r\n\r\n`), 413, 'angekündigte Größe');
    const first = 'x'.repeat(1024 * 1024);
    assert.equal(await rawStatus(mcp.port, `${head}Transfer-Encoding: chunked\r\n\r\n${first.length.toString(16)}\r\n${first}\r\na\r\n0123456789\r\n`), 413, 'ohne Größenangabe (chunked)');
  });

  test('Zustandslos: GET und DELETE auf /mcp enden ohne offenen Stream', async () => {
    for (const method of ['GET', 'DELETE']) {
      const response = await fetch(`${mcp.url}/mcp`, { method, headers: { Authorization: `Bearer ${fixture.tokens.a}`, Accept: 'text/event-stream' } });
      assert.equal(response.status, 405, method);
      await response.body?.cancel();
    }
  });

  test('X-Forwarded-For wird ohne MCP_TRUST_PROXY ignoriert: gefälschte Adressen umgehen das Rate-Limit nicht', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      statuses.push((await rawPost(mcp.url, { token: generateToken(), headers: { 'X-Forwarded-For': `203.0.113.${i}` } })).status);
    }
    assert.deepEqual(statuses, [401, 401, 401, 429, 429]);
  });
});

describe('Review-Befunde: Batches, Streams, Gleichzeitigkeit, Log', () => {
  test('JSON-RPC-Batches werden abgelehnt (sonst bis zu 100 Tool-Aufrufe je Request)', async () => {
    const call = (id: number) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'gsc_whoami', arguments: {} } });
    const response = await rawPost(mcp.url, { token: fixture.tokens.a, body: JSON.stringify([call(1), call(2)]) });
    assert.equal(response.status, 400);
    assert.match(await response.text(), /Batches/);
    assert.equal((await rawPost(mcp.url, { token: fixture.tokens.a, body: '{kaputt' })).status, 400);
  });

  test('subscriptions/listen öffnet keinen Stream, der einen Widerruf überdauern könnte', async () => {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'subscriptions/listen',
      params: {
        notifications: { toolsListChanged: true },
        _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientInfo': { name: 'x', version: '1' }, 'io.modelcontextprotocol/clientCapabilities': {} },
      },
    });
    const response = await rawPost(mcp.url, { token: fixture.tokens.a, body, headers: { 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'subscriptions/listen' } });
    // Die Antwort muss vollständig ankommen und enden; ein offener Stream würde hier hängen bleiben
    const text = await Promise.race([response.text(), new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Stream bleibt offen')), 3000))]);
    assert.match(text, /limit|error/i);
  });

  test('Höchstens 8 gleichzeitige Requests je Token; andere Tokens sind nicht betroffen', async () => {
    fixture.google.control.delayMs = 400;
    try {
      const call = (token: string, property: string) =>
        rawPost(mcp.url, { token, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'gsc_list_sitemaps', arguments: { property } } }) }).then(async (r) => {
          await r.text();
          return r.status;
        });
      const statuses = await Promise.all([...Array.from({ length: 12 }, () => call(fixture.tokens.a, 'sc-domain:kunde-a.example')), call(fixture.tokens.b, 'sc-domain:kunde-b.example')]);
      assert.equal(statuses.slice(0, 12).filter((s) => s === 429).length, 4);
      assert.equal(statuses[12], 200);
    } finally {
      fixture.google.control.delayMs = 0;
    }
  });

  test('Werte aus dem Request können keine Zeilen ins Server-Log schreiben', async () => {
    const { cleanLogLine } = await import('../src/http.ts');
    const line = cleanLogLine('Tool x\n[gsc-mcp] Freigaben neu geladen: 0 Tokens\u001b[31m');
    assert.ok(!/[\n\r\u001b]/.test(line), line);
    assert.ok(cleanLogLine('x'.repeat(10_000)).length <= 501);
  });
});

describe('Bausteine der Zugangsprüfung', () => {
  test('bearerToken akzeptiert nur das Token-Format dieses Dienstes', () => {
    const token = generateToken();
    assert.equal(bearerToken(`Bearer ${token}`), token);
    assert.equal(bearerToken(`bearer ${token}`), token);
    for (const header of [undefined, '', 'Bearer', `Bearer ${token} x`, `Basic ${token}`, `Bearer ${token}=`, 'Bearer gsc_kurz', `Bearer ${token.replace('gsc_', 'wcl_')}`]) {
      assert.equal(bearerToken(header), undefined, String(header));
    }
  });

  test('rateLimitKey kürzt IPv6 auf /64 und lehnt Nicht-Adressen ab', () => {
    assert.equal(rateLimitKey('203.0.113.9'), '203.0.113.9');
    assert.equal(rateLimitKey('::ffff:203.0.113.9'), '203.0.113.9');
    assert.equal(rateLimitKey('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
    assert.equal(rateLimitKey('2001:db8:1:2::9'), rateLimitKey('2001:db8:1:2:ffff::1'));
    assert.equal(rateLimitKey('nicht-ip'), undefined);
  });

  test('FailureLimiter: Fenster läuft ab', () => {
    let now = 0;
    const limiter = new FailureLimiter({ max: 2, windowMs: 1000, now: () => now });
    limiter.fail('x');
    limiter.fail('x');
    assert.ok(limiter.blockedFor('x') > 0);
    assert.equal(limiter.blockedFor('y'), 0);
    now = 1001;
    assert.equal(limiter.blockedFor('x'), 0);
  });
});

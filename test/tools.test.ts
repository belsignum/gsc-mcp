/**
 * Funktion der Tools gegen den Google-Nachbau, Audit-Log, Limits und Neuladen der Freigaben.
 */
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { generateToken, generateTokenId, hashToken, writeConfigFile } from '../src/tokens.ts';
import { urlInProperty } from '../src/tools.ts';
import { A_PREFIX, A_PROPERTY, B_PROPERTY, cleanup, connect, json, makeFixture, rawPost, startMcp, text, type Fixture } from './helpers.ts';

let fixture: Fixture;
let mcp: Awaited<ReturnType<typeof startMcp>>;

before(async () => {
  fixture = await makeFixture();
  mcp = await startMcp(fixture, { maxInspectionsPerDay: 3 });
});
after(async () => {
  await mcp.close();
  await cleanup(fixture);
});
beforeEach(() => fixture.google.reset());

async function auditLines(): Promise<any[]> {
  const files = (await readdir(fixture.auditDir)).filter((f) => f.endsWith('.jsonl'));
  const lines: any[] = [];
  for (const file of files) {
    for (const line of (await readFile(join(fixture.auditDir, file), 'utf8')).split('\n')) if (line) lines.push(JSON.parse(line));
  }
  return lines;
}

describe('Tools', () => {
  test('Tool-Liste: nur lesende Tools', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    const { tools } = await client.listTools();
    await client.close();
    assert.deepEqual(tools.map((t) => t.name).sort(), ['gsc_get_sitemap', 'gsc_inspect_url', 'gsc_list_properties', 'gsc_list_sitemaps', 'gsc_search_analytics', 'gsc_whoami']);
    for (const tool of tools) assert.equal(tool.annotations?.readOnlyHint, true, tool.name);
    for (const tool of tools) if (!['gsc_whoami', 'gsc_list_properties'].includes(tool.name)) assert.ok((tool.inputSchema.required ?? []).includes('property'), `${tool.name}: property muss Pflicht sein`);
  });

  test('gsc_search_analytics: Anfrage an Google und kompakte Zeilen', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    const result = json(
      await client.callTool({
        name: 'gsc_search_analytics',
        arguments: { property: A_PROPERTY, startDate: '2026-10-01', endDate: '2026-10-31', dimensions: ['query', 'page'], filters: [{ dimension: 'country', expression: 'deu' }], rowLimit: 2 },
      }),
    );
    await client.close();
    assert.equal(result.count, 2);
    assert.equal(result.hasMore, true);
    assert.deepEqual(result.rows[0], { query: 'query-0', page: 'page-0', clicks: 10, impressions: 100, ctr: 0.1, position: 1.23 });
    const request = fixture.google.apiRequests.find((r) => r.path.endsWith('/searchAnalytics/query'))!;
    assert.equal(request.path, `/webmasters/v3/sites/${encodeURIComponent(A_PROPERTY)}/searchAnalytics/query`);
    assert.deepEqual(request.body.dimensionFilterGroups, [{ groupType: 'and', filters: [{ dimension: 'country', operator: 'equals', expression: 'deu' }] }]);
    assert.equal(request.body.rowLimit, 2);
  });

  test('gsc_search_analytics: ungültige Eingaben lehnt der Server selbst ab', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    for (const args of [
      { startDate: '01.10.2026', endDate: '2026-10-31' },
      { startDate: '2026-02-30', endDate: '2026-03-01' },
      { startDate: '2026-10-31', endDate: '2026-10-01' },
      { startDate: '2026-10-01', endDate: '2026-10-31', rowLimit: 50_000 },
      { startDate: '2026-10-01', endDate: '2026-10-31', dimensions: ['query', 'query'] },
    ]) {
      const result = await client.callTool({ name: 'gsc_search_analytics', arguments: { property: A_PROPERTY, ...args } });
      assert.equal(result.isError, true, JSON.stringify(args));
    }
    await client.close();
    assert.equal(fixture.google.apiRequests.length, 0);
  });

  test('Sitemaps auflisten und lesen', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    const list = json(await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: A_PREFIX } }));
    assert.equal(list.count, 1);
    const one = json(await client.callTool({ name: 'gsc_get_sitemap', arguments: { property: A_PREFIX, feedpath: 'https://www.kunde-a.example/sitemap.xml' } }));
    assert.equal(one.path, 'https://www.kunde-a.example/sitemap.xml');
    await client.close();
  });

  test('gsc_inspect_url: URL muss zur Property gehören, sonst kein Request an Google', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    const outside = await client.callTool({ name: 'gsc_inspect_url', arguments: { property: A_PREFIX, url: 'https://shop.kunde-a.example/' } });
    assert.match(text(outside), /gehört nicht zu dieser Property/);
    const foreign = await client.callTool({ name: 'gsc_inspect_url', arguments: { property: A_PROPERTY, url: 'https://www.kunde-b.example/' } });
    assert.match(text(foreign), /gehört nicht zu dieser Property/);
    assert.equal(fixture.google.requestCount, 0);
    const inside = json(await client.callTool({ name: 'gsc_inspect_url', arguments: { property: A_PROPERTY, url: 'https://shop.kunde-a.example/produkt' } }));
    assert.equal(inside.indexStatusResult.verdict, 'PASS');
    await client.close();
  });

  test('urlInProperty: Domain mit Subdomains, URL-Präfix nur darunter', () => {
    assert.equal(urlInProperty('https://kunde-a.example/', 'sc-domain:kunde-a.example'), true);
    assert.equal(urlInProperty('http://a.b.kunde-a.example/x', 'sc-domain:kunde-a.example'), true);
    assert.equal(urlInProperty('https://evilkunde-a.example/', 'sc-domain:kunde-a.example'), false);
    assert.equal(urlInProperty('https://kunde-a.example.evil.example/', 'sc-domain:kunde-a.example'), false);
    assert.equal(urlInProperty('ftp://kunde-a.example/', 'sc-domain:kunde-a.example'), false);
    assert.equal(urlInProperty('https://www.kunde-a.example', 'https://www.kunde-a.example/'), true);
    assert.equal(urlInProperty('https://www.kunde-a.example/shop/a', 'https://www.kunde-a.example/shop/'), true);
    assert.equal(urlInProperty('https://www.kunde-a.example/shopping', 'https://www.kunde-a.example/shop/'), false);
    assert.equal(urlInProperty('https://www.kunde-a.example@evil.example/', 'https://www.kunde-a.example/'), false);
  });

  test('URL-Prüfungen sind je Mandant begrenzt; andere Mandanten bleiben unberührt', async () => {
    const client = await connect(mcp.url, fixture.tokens.a2);
    let limited = 0;
    for (let i = 0; i < 5; i++) {
      const result = await client.callTool({ name: 'gsc_inspect_url', arguments: { property: A_PREFIX, url: `https://www.kunde-a.example/${i}` } });
      if (result.isError) {
        assert.match(text(result), /Limit erreicht/);
        limited += 1;
      }
    }
    await client.close();
    // Limit 3 je Mandant; der Test davor hat für kunde-a schon eine Prüfung verbraucht
    assert.equal(limited, 3);
    const other = await connect(mcp.url, fixture.tokens.b);
    json(await other.callTool({ name: 'gsc_inspect_url', arguments: { property: B_PROPERTY, url: 'https://kunde-b.example/' } }));
    await other.close();
  });

  test('Google-Fehler: Kontingent, Störung und Anmeldefehler werden übersetzt, nie als Daten durchgereicht', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    // gaxios wiederholt einen Abruf einmal; erst der zweite Fehler kommt beim Nutzer an
    const quota = { status: 429, body: { error: { code: 429, message: 'Quota exceeded', status: 'RESOURCE_EXHAUSTED' } } };
    fixture.google.forced.push(quota, quota);
    assert.match(text(await client.callTool({ name: 'gsc_list_properties', arguments: {} })), /Kontingent/);
    fixture.google.forced.push({ status: 503, body: { error: { code: 503, message: 'backend' } } }, { status: 503, body: { error: { code: 503, message: 'backend' } } });
    assert.match(text(await client.callTool({ name: 'gsc_list_properties', arguments: {} })), /nicht erreichbar/);
    fixture.google.forced.push({ status: 400, body: { error: { code: 400, message: 'Invalid dimension: hour' } } });
    assert.match(text(await client.callTool({ name: 'gsc_search_analytics', arguments: { property: A_PROPERTY, startDate: '2026-10-01', endDate: '2026-10-02', dimensions: ['hour'] } })), /Invalid dimension/);
    await client.close();
  });
});

describe('Audit-Log', () => {
  test('Jeder Aufruf steht im Log, mit Ergebnis und internem Grund – nie Token, Hash oder gelieferte Daten', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    await client.callTool({ name: 'gsc_whoami', arguments: {} });
    await client.callTool({ name: 'gsc_search_analytics', arguments: { property: A_PROPERTY, startDate: '2026-10-01', endDate: '2026-10-02', dimensions: ['query'] } });
    await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: B_PROPERTY } });
    await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: 'sc-domain:ohne-zugriff.example' } });
    await client.close();

    const lines = await auditLines();
    const calls = lines.filter((l) => l.kind === 'call' && l.user === 'anna');
    const whoami = calls.findLast((l) => l.tool === 'gsc_whoami');
    assert.equal(whoami.result, 'ok');
    const query = calls.findLast((l) => l.tool === 'gsc_search_analytics' && l.result === 'ok');
    assert.equal(query.property, A_PROPERTY);
    assert.equal(query.rows, 3);
    assert.deepEqual(query.params.dimensions, ['query']);
    assert.equal(typeof query.ms, 'number');
    assert.equal(query.tenant, 'kunde-a');
    const whitelist = calls.findLast((l) => l.property === B_PROPERTY);
    assert.deepEqual([whitelist.result, whitelist.reason], ['denied', 'whitelist']);
    const google = calls.findLast((l) => l.property === 'sc-domain:ohne-zugriff.example');
    assert.deepEqual([google.result, google.reason], ['denied', 'google_403']);

    const raw = (await Promise.all((await readdir(fixture.auditDir)).map((f) => readFile(join(fixture.auditDir, f), 'utf8')))).join('');
    for (const secret of [fixture.tokens.a, fixture.tokens.b, hashToken(fixture.tokens.a), 'query-0', 'ya29.', 'PRIVATE KEY']) {
      assert.ok(!raw.includes(secret), `Audit-Log enthält ${secret.slice(0, 12)}…`);
    }
    const mode = (await import('node:fs/promises')).stat(join(fixture.auditDir, (await readdir(fixture.auditDir))[0]));
    assert.equal((await mode).mode & 0o777, 0o600);
  });

  test('Volles Audit-Log: keine Daten, kein Request an Google', async () => {
    const full = await startMcp(fixture, { auditMaxBytes: 1 });
    try {
      fixture.google.reset();
      const client = await connect(full.url, fixture.tokens.a);
      const result = await client.callTool({ name: 'gsc_list_properties', arguments: {} });
      await client.close();
      assert.equal(result.isError, true);
      assert.match(text(result), /protokolliert/);
      assert.equal(fixture.google.requestCount, 0);
    } finally {
      await full.close();
    }
  });
});

describe('Freigaben neu laden', () => {
  test('Widerruf und neue Tokens wirken ohne Neustart; fehlerhafte Datei sperrt alle aus', async () => {
    const { readConfigFile } = await import('../src/tokens.ts');
    const { writeFile } = await import('node:fs/promises');
    const original = await readConfigFile(fixture.configFile);
    const fresh = generateToken();
    try {
      // Token von ben widerrufen, einen neuen anlegen
      const changed = structuredClone(original);
      changed.tokens = changed.tokens.filter((t) => t.user !== 'ben');
      changed.tokens.push({ id: generateTokenId(), user: 'carla', tenant: 'kunde-b', properties: [B_PROPERTY], token_sha256: hashToken(fresh) });
      await writeConfigFile(fixture.configFile, changed);
      assert.equal((await rawPost(mcp.url, { token: fixture.tokens.b })).status, 401);
      assert.equal((await rawPost(mcp.url, { token: fresh })).status, 200);

      // Kaputte Datei: niemand kommt herein, auch nicht mit gültigem Token
      await writeFile(fixture.configFile, 'version: 1\ntokens: [\n');
      assert.equal((await rawPost(mcp.url, { token: fixture.tokens.a })).status, 503);
    } finally {
      await writeConfigFile(fixture.configFile, original);
    }
    assert.equal((await rawPost(mcp.url, { token: fixture.tokens.a })).status, 200);
    assert.equal((await rawPost(mcp.url, { token: fixture.tokens.b })).status, 200);
  });
});

describe('Einordnung von Google-Fehlern', () => {
  test('403/404 werden neutral, Anmeldefehler und Kontingent nicht', async () => {
    const { classify, TOKEN_URL } = await import('../src/google.ts');
    const api = 'https://searchconsole.googleapis.com/webmasters/v3/sites/x';
    assert.equal(classify({ config: { url: TOKEN_URL }, response: { status: 400, data: { error: 'invalid_grant', error_description: 'Invalid JWT Signature.' } } }).kind, 'auth');
    assert.equal(classify({ config: { url: api }, response: { status: 403, data: { error: { code: 403, errors: [{ reason: 'forbidden' }] } } } }).kind, 'denied');
    assert.equal(classify({ config: { url: api }, response: { status: 404, data: { error: { code: 404 } } } }).kind, 'denied');
    assert.equal(classify({ config: { url: api }, response: { status: 403, data: { error: { code: 403, errors: [{ reason: 'quotaExceeded' }] } } } }).kind, 'quota');
    assert.equal(classify({ config: { url: api }, response: { status: 401, data: { error: { code: 401 } } } }).kind, 'auth');
    assert.equal(classify({ code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' }).kind, 'unavailable');
    const denied = classify({ config: { url: api }, response: { status: 403, data: { error: { message: "User does not have sufficient permission for site 'sc-domain:kunde-b.example'." } } } });
    assert.equal(denied.message, 'denied'); // die Google-Meldung mit dem Property-Namen geht nur ins Protokoll
  });
});

describe('Aufruflimit je Token', () => {
  test('Jeder Aufruf zählt, auch abgelehnte; danach kein Request an Google, andere Tokens bleiben nutzbar', async () => {
    const limited = await startMcp(fixture, { maxCallsPerMinute: 3 });
    try {
      fixture.google.reset();
      const before = (await auditLines()).length;
      const client = await connect(limited.url, fixture.tokens.a);
      const results = [];
      // zwei abgelehnte (fremde Property) und ein erlaubter Aufruf verbrauchen das Limit
      results.push(await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: B_PROPERTY } }));
      results.push(await client.callTool({ name: 'gsc_whoami', arguments: {} }));
      results.push(await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: A_PROPERTY } }));
      for (let i = 0; i < 5; i++) results.push(await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: i % 2 ? A_PROPERTY : B_PROPERTY } }));
      assert.deepEqual(results.map((r) => Boolean(r.isError)), [true, false, false, true, true, true, true, true]);
      for (const r of results.slice(3)) assert.match(text(r), /höchstens 3 Aufrufe pro Minute/);
      assert.equal(fixture.google.apiRequests.length, 1);
      await client.close();
      // Ins Audit-Log kommen die drei Aufrufe und nur die erste Ablehnung wegen des Limits
      const added = (await auditLines()).slice(before);
      assert.equal(added.length, 4);
      assert.equal(added.filter((l) => l.reason === 'limit').length, 1);
      const other = await connect(limited.url, fixture.tokens.b);
      json(await other.callTool({ name: 'gsc_list_sitemaps', arguments: { property: B_PROPERTY } }));
      await other.close();
    } finally {
      await limited.close();
    }
  });

  test('Tageslimit', async () => {
    const limited = await startMcp(fixture, { maxCallsPerDay: 2 });
    try {
      const client = await connect(limited.url, fixture.tokens.a2);
      for (let i = 0; i < 2; i++) json(await client.callTool({ name: 'gsc_whoami', arguments: {} }));
      assert.match(text(await client.callTool({ name: 'gsc_whoami', arguments: {} })), /höchstens 2 Aufrufe pro Tag/);
      await client.close();
    } finally {
      await limited.close();
    }
  });

  test('Audit-Zeilen bleiben klein, auch mit langen Filtern', async () => {
    const client = await connect(mcp.url, fixture.tokens.a2);
    const filters = Array.from({ length: 20 }, () => ({ dimension: 'query', operator: 'contains', expression: 'x'.repeat(4000) }));
    await client.callTool({ name: 'gsc_search_analytics', arguments: { property: B_PROPERTY, startDate: '2026-10-01', endDate: '2026-10-02', filters } });
    await client.close();
    const files = (await readdir(fixture.auditDir)).filter((f) => f.endsWith('.jsonl'));
    const lines = (await Promise.all(files.map((f) => readFile(join(fixture.auditDir, f), 'utf8')))).join('').split('\n').filter(Boolean);
    for (const line of lines) assert.ok(Buffer.byteLength(line) <= 2048, `Zeile mit ${Buffer.byteLength(line)} Bytes`);
    const last = JSON.parse(lines.findLast((l) => l.includes('gsc_search_analytics') && l.includes(B_PROPERTY))!);
    assert.equal(last.result, 'denied');
  });
});

describe('Debug-Logging der Google-Bibliotheken', () => {
  test('GOOGLE_SDK_NODE_LOGGING ist abgeschaltet, bevor die Google-Bibliotheken laden (würde Access Tokens loggen)', async () => {
    const { execFileSync } = await import('node:child_process');
    const script = `
      await import(${JSON.stringify(new URL('../src/google.ts', import.meta.url).href)});
      const { log, placeholder } = await import('google-logging-utils');
      process.stdout.write(JSON.stringify({ env: process.env.GOOGLE_SDK_NODE_LOGGING ?? null, quiet: log('auth') === placeholder }));`;
    const output = execFileSync(process.execPath, ['--input-type=module', '-e', script], {
      env: { ...process.env, GOOGLE_SDK_NODE_LOGGING: '*' },
      cwd: new URL('..', import.meta.url),
      stdio: ['ignore', 'pipe', 'ignore'],
    }).toString();
    assert.deepEqual(JSON.parse(output), { env: null, quiet: true });
  });
});

/**
 * Mandantentrennung: die Pflicht-Tests des PR-Checks.
 *
 * Ebene 1 (Dienst): Property-Whitelist je Token, exakter Vergleich, neutrale Ablehnung ohne Request an Google.
 * Ebene 2 (Google): jeder Aufruf nutzt den Service Account des Mandanten, Scope nur webmasters.readonly.
 */
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { SCOPE } from '../src/google.ts';
import { NOT_AVAILABLE_TEXT } from '../src/tools.ts';
import { A_NOT_SHARED, A_PREFIX, A_PROPERTY, B_PROPERTY, cleanup, connect, json, makeFixture, NOWHERE, rawPost, rawToolCall, startMcp, text, type Fixture } from './helpers.ts';

let fixture: Fixture;
let mcp: Awaited<ReturnType<typeof startMcp>>;

before(async () => {
  fixture = await makeFixture();
  mcp = await startMcp(fixture, { maxAuthFailures: 5 });
});
after(async () => {
  await mcp.close();
  await cleanup(fixture);
});
beforeEach(() => fixture.google.reset());

const PROPERTY_TOOLS: Array<[string, Record<string, unknown>]> = [
  ['gsc_search_analytics', { startDate: '2026-10-01', endDate: '2026-10-31', dimensions: ['query'] }],
  ['gsc_list_sitemaps', {}],
  ['gsc_get_sitemap', { feedpath: 'https://www.kunde-b.example/sitemap.xml' }],
  ['gsc_inspect_url', { url: 'https://www.kunde-b.example/' }],
];

describe('Ebene 1: Whitelist je Token', () => {
  test('Token A + Property von Mandant B: exakt dieselbe Antwort wie für eine Property, die es nicht gibt – und kein Request an Google', async () => {
    for (const [tool, args] of PROPERTY_TOOLS) {
      const foreign = await rawToolCall(mcp.url, fixture.tokens.a, tool, { ...args, property: B_PROPERTY });
      const missing = await rawToolCall(mcp.url, fixture.tokens.a, tool, { ...args, property: NOWHERE });
      assert.equal(foreign.status, 200, tool);
      assert.deepEqual(foreign.result, missing.result, `${tool}: Antworten unterscheiden sich`);
      assert.equal(foreign.raw, missing.raw, `${tool}: Antworten unterscheiden sich in der Leitung`);
      assert.deepEqual(foreign.result, { content: [{ type: 'text', text: NOT_AVAILABLE_TEXT }], isError: true });
    }
    assert.equal(fixture.google.requestCount, 0, 'Google darf bei einer nicht freigegebenen Property keinen Request bekommen');
  });

  test('Freigegeben, aber bei Google ohne Zugriff (403): wieder dieselbe Antwort', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    const google403 = await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: 'sc-domain:ohne-zugriff.example' } });
    const whitelist = await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: B_PROPERTY } });
    await client.close();
    assert.ok(fixture.google.apiRequests.some((r) => r.path.includes('ohne-zugriff')), 'der erste Aufruf muss Google erreicht haben');
    assert.deepEqual(google403, whitelist);
    assert.equal(text(google403), NOT_AVAILABLE_TEXT);
  });

  test('Exakter Vergleich: keine Subdomain, kein Präfix, keine andere Schreibweise', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    for (const property of [
      'sc-domain:shop.kunde-a.example', // Subdomain einer freigegebenen Domain-Property
      'sc-domain:kunde-a.example.evil.example',
      'SC-DOMAIN:kunde-a.example',
      'sc-domain:Kunde-A.example',
      `${A_PROPERTY} `,
      ` ${A_PROPERTY}`,
      `${A_PREFIX}shop/`, // Unterverzeichnis einer freigegebenen URL-Präfix-Property
      'https://www.kunde-a.example', // ohne Schrägstrich
      'http://www.kunde-a.example/',
      'https://WWW.kunde-a.example/',
      A_NOT_SHARED, // sieht der Service Account, ist aber nicht freigegeben
      'sc-domain:kunde-a.example\u0000',
    ]) {
      const result = await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property } });
      assert.equal(text(result), NOT_AVAILABLE_TEXT, property);
    }
    await client.close();
    assert.equal(fixture.google.requestCount, 0);
  });

  test('gsc_list_properties liefert nur die Schnittmenge aus Whitelist und Google', async () => {
    const client = await connect(mcp.url, fixture.tokens.a);
    const result = json(await client.callTool({ name: 'gsc_list_properties', arguments: {} }));
    await client.close();
    // Google liefert für kunde-a drei Properties; freigegeben sind A_PROPERTY, A_PREFIX und eine, die Google nicht kennt
    assert.deepEqual(result.properties.map((p: { property: string }) => p.property).sort(), [A_PROPERTY, A_PREFIX].sort());
    assert.equal(result.count, 2);
    assert.doesNotMatch(JSON.stringify(result), /blog\.kunde-a|ohne-zugriff|kunde-b/);
  });

  test('Zweiter Token desselben Mandanten hat seine eigene, engere Whitelist', async () => {
    const client = await connect(mcp.url, fixture.tokens.a2);
    assert.equal(text(await client.callTool({ name: 'gsc_list_sitemaps', arguments: { property: A_PROPERTY } })), NOT_AVAILABLE_TEXT);
    assert.equal(fixture.google.requestCount, 0);
    const listed = json(await client.callTool({ name: 'gsc_list_properties', arguments: {} }));
    assert.deepEqual(listed.properties.map((p: { property: string }) => p.property), [A_PREFIX]);
    await client.close();
  });

  test('gsc_whoami zeigt nur die eigene Freigabe und fragt Google nicht', async () => {
    const client = await connect(mcp.url, fixture.tokens.b);
    const me = json(await client.callTool({ name: 'gsc_whoami', arguments: {} }));
    await client.close();
    assert.deepEqual(me, { user: 'ben', tenant: 'kunde-b', properties: [B_PROPERTY] });
    assert.equal(fixture.google.requestCount, 0);
  });
});

describe('Ebene 2: Service Account je Mandant', () => {
  test('Angefordert wird nur der Scope webmasters.readonly (am JWT geprüft)', async () => {
    for (const token of [fixture.tokens.a, fixture.tokens.b]) {
      const client = await connect(mcp.url, token);
      json(await client.callTool({ name: 'gsc_list_properties', arguments: {} }));
      await client.close();
    }
    assert.ok(fixture.google.tokenRequests.length >= 1);
    for (const request of fixture.google.tokenRequests) {
      assert.equal(request.scope, SCOPE);
      assert.equal(request.scope, 'https://www.googleapis.com/auth/webmasters.readonly');
      assert.equal(request.aud, 'https://oauth2.googleapis.com/token');
      assert.ok(request.lifetime <= 3600);
    }
  });

  test('Aufrufe mit Token A nutzen den Schlüssel von Mandant A, Token B den von B – nie den anderen', async () => {
    const calls: Array<[string, string, Record<string, unknown>]> = [
      [fixture.tokens.a, 'gsc_search_analytics', { property: A_PROPERTY, startDate: '2026-10-01', endDate: '2026-10-02' }],
      [fixture.tokens.b, 'gsc_search_analytics', { property: B_PROPERTY, startDate: '2026-10-01', endDate: '2026-10-02' }],
      [fixture.tokens.a2, 'gsc_list_sitemaps', { property: A_PREFIX }],
      [fixture.tokens.b, 'gsc_inspect_url', { property: B_PROPERTY, url: 'https://kunde-b.example/seite' }],
      [fixture.tokens.a, 'gsc_list_properties', {}],
    ];
    const expected = new Map([
      [fixture.tokens.a, fixture.accounts.a.email],
      [fixture.tokens.a2, fixture.accounts.a.email],
      [fixture.tokens.b, fixture.accounts.b.email],
    ]);
    for (const [token, name, args] of calls) {
      const before = fixture.google.apiRequests.length;
      const client = await connect(mcp.url, token);
      json(await client.callTool({ name, arguments: args }));
      await client.close();
      const made = fixture.google.apiRequests.slice(before);
      assert.ok(made.length > 0, `${name}: kein API-Request`);
      for (const request of made) assert.equal(request.account, expected.get(token), `${name} lief mit dem falschen Service Account`);
    }
    const issuers = new Set(fixture.google.tokenRequests.map((r) => r.iss));
    assert.ok([...issuers].every((iss) => iss === fixture.accounts.a.email || iss === fixture.accounts.b.email));
  });

  test('Ein vertauschter Schlüssel öffnet keinen fremden Mandanten', async () => {
    const { writeKey } = await import('./mock-google.ts');
    const { rename } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const keyA = join(fixture.keyDir, 'kunde-a.json');
    await rename(keyA, `${keyA}.bak`);
    await writeKey(fixture.keyDir, 'kunde-a', fixture.accounts.b); // Schlüssel von B unter dem Namen von A
    try {
      fixture.google.reset();
      const client = await connect(mcp.url, fixture.tokens.a);
      const result = await client.callTool({ name: 'gsc_list_properties', arguments: {} });
      await client.close();
      assert.equal(result.isError, true);
      assert.match(text(result), /nicht eingerichtet/);
      assert.equal(fixture.google.requestCount, 0, 'mit dem falschen Schlüssel darf nichts an Google gehen');
    } finally {
      await rename(`${keyA}.bak`, keyA);
    }
  });
});

describe('Zugang', () => {
  test('Unbekannter Token: 401, zählt gegen das Rate-Limit; gültige Tokens arbeiten weiter', async () => {
    const { generateToken } = await import('../src/tokens.ts');
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await rawPost(mcp.url, { token: generateToken() })).status);
    assert.deepEqual(statuses, [401, 401, 401, 401, 401, 429, 429]);
    assert.equal((await rawPost(mcp.url, { token: fixture.tokens.a })).status, 200);
    assert.equal(fixture.google.requestCount, 0);
  });

  test('Ohne Token oder mit fremdem Format: 401, ohne Tool-Liste', async () => {
    for (const headers of [{}, { Authorization: 'Bearer' }, { Authorization: 'Basic abc' }, { Authorization: `Bearer ${fixture.tokens.a.slice(0, -1)}` }]) {
      const response = await rawPost(mcp.url, { headers });
      assert.equal(response.status, 401);
      assert.doesNotMatch(await response.text(), /gsc_search_analytics/);
    }
  });
});

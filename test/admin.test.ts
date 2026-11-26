/**
 * gsc-admin: Mandanten mit Schlüssel per stdin, Tokens nur als Hash, Audit-Einträge ohne Geheimnisse.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { runAdmin } from '../src/admin.ts';
import { hashToken, readConfigFile, TOKEN_PATTERN } from '../src/tokens.ts';
import { keyJson, makeServiceAccount } from './mock-google.ts';

let dir: string;
let env: NodeJS.ProcessEnv;
const accountA = makeServiceAccount('gsc-kunde-a@test-project.iam.gserviceaccount.com', {});
const accountB = makeServiceAccount('gsc-kunde-b@test-project.iam.gserviceaccount.com', {});

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'gsc-admin-test-'));
  await mkdir(join(dir, 'config'));
  await mkdir(join(dir, 'keys'), { mode: 0o700 });
  env = { GSC_CONFIG: join(dir, 'config', 'tokens.yaml'), GSC_KEY_DIR: join(dir, 'keys'), GSC_AUDIT_DIR: join(dir, 'audit') };
});
after(() => rm(dir, { recursive: true, force: true }));

async function admin(args: string, stdin = '') {
  let out = '';
  let err = '';
  const code = await runAdmin(args.split(' ').filter(Boolean), {
    env,
    stdin: Object.assign(Readable.from(stdin ? [Buffer.from(stdin)] : []), { isTTY: false }),
    out: (t) => (out += t),
    err: (t) => (err += t),
  });
  return { code, out, err };
}

describe('gsc-admin', () => {
  test('tenant add: Schlüssel von stdin, gespeichert mit 0600, Service Account in der Freigabedatei', async () => {
    const result = await admin('tenant add kunde-a', keyJson(accountA));
    assert.equal(result.code, 0, result.err);
    const key = JSON.parse(await readFile(join(dir, 'keys', 'kunde-a.json'), 'utf8'));
    assert.equal(key.client_email, accountA.email);
    assert.equal(key.project_id, undefined, 'nur die nötigen Felder werden gespeichert');
    assert.equal((await stat(join(dir, 'keys', 'kunde-a.json'))).mode & 0o777, 0o600);
    const config = await readConfigFile(env.GSC_CONFIG!);
    assert.deepEqual(config.tenants, { 'kunde-a': { service_account: accountA.email } });
  });

  test('tenant add: kein Schlüssel, falscher Typ, doppelter Mandant oder fremder Service Account doppelt', async () => {
    assert.equal((await admin('tenant add kunde-x')).code, 2);
    assert.equal((await admin('tenant add kunde-x', '{"type":"authorized_user"}')).code, 1);
    assert.equal((await admin('tenant add ../evil', keyJson(accountB))).code, 2);
    assert.equal((await admin('tenant add kunde-a', keyJson(accountB))).code, 2);
    const reused = await admin('tenant add kunde-c', keyJson(accountA));
    assert.equal(reused.code, 2);
    assert.match(reused.err, /gehört schon zum Mandanten kunde-a/);
    assert.equal((await admin('tenant add kunde-b', keyJson(accountB))).code, 0);
  });

  test('tenant key: nur ein Schlüssel desselben Service Accounts', async () => {
    assert.equal((await admin('tenant key kunde-a', keyJson(accountB))).code, 2);
    const rotated = { ...accountA, keyId: 'ab'.repeat(20) };
    assert.equal((await admin('tenant key kunde-a', keyJson(rotated))).code, 0);
    assert.equal(JSON.parse(await readFile(join(dir, 'keys', 'kunde-a.json'), 'utf8')).private_key_id, 'ab'.repeat(20));
  });

  test('token add: Token genau einmal auf stdout, in der Datei nur der Hash', async () => {
    const result = await admin('token add --user anna --tenant kunde-a --property sc-domain:kunde-a.example --property https://www.kunde-a.example/');
    assert.equal(result.code, 0, result.err);
    const token = result.out.trim();
    assert.match(token, TOKEN_PATTERN);
    assert.ok(!result.err.includes(token));
    const file = await readFile(env.GSC_CONFIG!, 'utf8');
    assert.ok(!file.includes(token), 'Token im Klartext gespeichert');
    assert.ok(file.includes(hashToken(token)));
    const config = await readConfigFile(env.GSC_CONFIG!);
    assert.deepEqual(config.tokens[0].properties, ['sc-domain:kunde-a.example', 'https://www.kunde-a.example/']);
    // token list zeigt weder Token noch Hash
    const list = await admin('token list');
    assert.match(list.out, /anna\tkunde-a/);
    assert.ok(!list.out.includes(token) && !list.out.includes(hashToken(token)));
  });

  test('token add: Properties nur in exakter Search-Console-Schreibweise', async () => {
    for (const property of ['example.com', 'sc-domain:Example.com', 'https://www.example.com', 'https://WWW.example.com/', 'https://www.example.com/?a=1', 'ftp://example.com/', 'sc-domain:']) {
      const result = await admin(`token add --user anna --tenant kunde-a --property ${property}`);
      assert.equal(result.code, 2, property);
      assert.equal(result.out, '', 'bei einem Fehler darf kein Token ausgegeben werden');
    }
    assert.equal((await admin('token add --user anna --tenant kunde-z --property sc-domain:example.com')).code, 2);
    assert.equal((await admin('token add --user "anna b" --tenant kunde-a --property sc-domain:example.com')).code, 2);
  });

  test('token properties und token revoke', async () => {
    const config = await readConfigFile(env.GSC_CONFIG!);
    const id = config.tokens[0].id;
    assert.equal((await admin(`token properties ${id} --property sc-domain:kunde-a.example`)).code, 0);
    assert.deepEqual((await readConfigFile(env.GSC_CONFIG!)).tokens[0].properties, ['sc-domain:kunde-a.example']);
    assert.equal((await admin('tenant remove kunde-a')).code, 2, 'Mandant mit Tokens darf nicht gelöscht werden');
    assert.equal((await admin(`token revoke ${id}`)).code, 0);
    assert.equal((await readConfigFile(env.GSC_CONFIG!)).tokens.length, 0);
    assert.equal((await admin(`token revoke ${id}`)).code, 2);
  });

  test('check meldet fehlende oder vertauschte Schlüssel', async () => {
    assert.equal((await admin('check')).code, 0);
    await rm(join(dir, 'keys', 'kunde-b.json'));
    const missing = await admin('check');
    assert.equal(missing.code, 1);
    assert.match(missing.out, /kunde-b: Schlüssel fehlt/);
  });

  test('tenant remove löscht Mandant und Schlüssel', async () => {
    assert.equal((await admin('tenant remove kunde-a')).code, 0);
    await assert.rejects(stat(join(dir, 'keys', 'kunde-a.json')));
    assert.deepEqual(Object.keys((await readConfigFile(env.GSC_CONFIG!)).tenants), ['kunde-b']);
  });

  test('Audit-Log: jede Änderung steht drin, kein Token, Hash oder Schlüssel', async () => {
    const files = await readdir(join(dir, 'audit'));
    const raw = (await Promise.all(files.map((f) => readFile(join(dir, 'audit', f), 'utf8')))).join('');
    const actions = raw.split('\n').filter(Boolean).map((l) => JSON.parse(l).action);
    for (const action of ['tenant.add', 'tenant.key', 'token.add', 'token.properties', 'token.revoke', 'tenant.remove']) assert.ok(actions.includes(action), action);
    assert.doesNotMatch(raw, /gsc_[A-Za-z0-9_-]{43}|PRIVATE KEY|[0-9a-f]{64}/);
  });

  test('Unbekannte Befehle und Optionen', async () => {
    assert.equal((await admin('token delete x')).code, 2);
    assert.equal((await admin('token add --admin')).code, 2);
    assert.equal((await admin('--help')).code, 0);
  });
});

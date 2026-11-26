/**
 * Statische Prüfung von Dockerfile, Compose-Dateien und Workflows: die Härtung darf nicht unbemerkt verloren gehen.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { parse } from 'yaml';

async function compose(file: string): Promise<any> {
  return parse(await readFile(new URL(`../${file}`, import.meta.url), 'utf8'));
}

const FILES = ['docker-compose.yml', 'docker-compose.nginx.yml'];
const OWN = ['gsc-mcp', 'egress', 'ingress', 'gsc-admin'];

function commandOf(service: any): string[] {
  return [...(service.entrypoint ?? []), ...(service.command ?? [])];
}

test('Compose: jeder Container läuft eingeschränkt', async () => {
  for (const file of FILES) {
    const { services } = await compose(file);
    for (const [name, service] of Object.entries<any>(services)) {
      assert.equal(service.read_only, true, `${file} ${name}: read_only`);
      assert.deepEqual(service.cap_drop, ['ALL'], `${file} ${name}: cap_drop`);
      assert.ok(service.security_opt?.includes('no-new-privileges:true'), `${file} ${name}: no-new-privileges`);
      assert.ok(service.pids_limit > 0 && service.pids_limit <= 200, `${file} ${name}: pids_limit`);
      assert.ok(service.mem_limit, `${file} ${name}: mem_limit`);
      if (name !== 'gsc-admin') {
        assert.ok(service.cpus, `${file} ${name}: cpus`);
        assert.equal(service.logging?.options?.['max-size'], '1m', `${file} ${name}: Log-Limit`);
      }
      assert.ok(!service.privileged, `${file} ${name}: privileged`);
      if (name !== 'caddy') assert.equal(service.cap_add, undefined, `${file} ${name}: cap_add`);
    }
  }
});

test('Compose: der Server hängt nur am internen Netz, ohne Ports; internal ist wirklich intern', async () => {
  for (const file of FILES) {
    const config = await compose(file);
    const server = config.services['gsc-mcp'];
    assert.deepEqual(server.networks, ['internal'], `${file}: Server-Netze`);
    assert.equal(server.ports, undefined, `${file}: Server darf keine Ports veröffentlichen`);
    assert.equal(server.network_mode, undefined);
    assert.equal(config.networks.internal.internal, true, `${file}: Netz internal muss internal: true sein`);
    // ohne inhibit_ipv4 wären Dienste des Hosts über die Gateway-Adresse des Netzes erreichbar
    assert.equal(config.networks.internal.driver_opts?.['com.docker.network.bridge.inhibit_ipv4'], 'true', `${file}: inhibit_ipv4`);
    assert.equal(server.environment.GSC_EGRESS_PROXY, 'http://egress:3128');
  }
});

test('Compose: Egress-Allowlist enthält genau die beiden Google-Ziele', async () => {
  for (const file of FILES) {
    const egress = (await compose(file)).services.egress;
    assert.equal(egress.environment.EGRESS_ALLOW, 'oauth2.googleapis.com:443,searchconsole.googleapis.com:443', file);
    assert.equal(egress.ports, undefined, `${file}: Egress darf keine Ports veröffentlichen`);
    assert.deepEqual(egress.networks, ['internal', 'outbound']);
  }
});

test('Compose: Freigaben und Schlüssel sind im Server nur lesbar; schreiben darf nur gsc-admin, ohne Netzwerk', async () => {
  for (const file of FILES) {
    const { services } = await compose(file);
    const server = services['gsc-mcp'];
    assert.ok(server.volumes.includes('gsc_config:/config:ro'), `${file}: /config muss :ro sein`);
    assert.ok(server.volumes.includes('gsc_keys:/run/secrets/gsc:ro'), `${file}: Schlüssel müssen :ro sein`);
    const admin = services['gsc-admin'];
    assert.equal(admin.network_mode, 'none', `${file}: gsc-admin ohne Netzwerk`);
    assert.deepEqual(admin.profiles, ['admin'], `${file}: gsc-admin startet nicht mit up`);
    for (const [name, service] of Object.entries<any>(services)) {
      if (name === 'gsc-mcp' || name === 'gsc-admin') continue;
      const mounts = (service.volumes ?? []).join(' ');
      assert.doesNotMatch(mounts, /gsc_keys|gsc_config|audit_data/, `${file} ${name}: darf weder Schlüssel noch Freigaben sehen`);
    }
  }
});

test('Compose: eigene Container laufen mit Node Permission Model und ohne eval', async () => {
  const dockerfile = await readFile(new URL('../Dockerfile', import.meta.url), 'utf8');
  const cmd = JSON.parse(/^CMD (\[.*\])$/m.exec(dockerfile)![1]) as string[];
  for (const args of [cmd]) {
    assert.ok(args.includes('--permission') && args.includes('--disallow-code-generation-from-strings'));
    assert.ok(!args.some((a) => /--allow-(child-process|worker|addons|wasi|inspector)/.test(a)));
    assert.deepEqual(args.filter((a) => a.startsWith('--allow-fs-write')), ['--allow-fs-write=/data/audit/']);
  }
  for (const file of FILES) {
    const { services } = await compose(file);
    for (const name of OWN) {
      const service = services[name];
      if (!service || name === 'gsc-mcp') continue;
      const args = commandOf(service);
      assert.ok(args.includes('--permission'), `${file} ${name}: --permission`);
      assert.ok(args.includes('--disallow-code-generation-from-strings'), `${file} ${name}: eval`);
      assert.ok(!args.some((a) => /--allow-(child-process|worker|addons|wasi|inspector)/.test(a)), `${file} ${name}`);
      if (name !== 'gsc-admin') assert.ok(!args.some((a) => a.startsWith('--allow-fs-write')), `${file} ${name}: darf nichts schreiben`);
    }
  }
});

test('Compose hinter vorhandenem NGINX: Port nur über die Weiterleitung und nur auf 127.0.0.1', async () => {
  const { services } = await compose('docker-compose.nginx.yml');
  assert.equal(services.caddy, undefined);
  const published = Object.entries<any>(services).filter(([, s]) => s.ports);
  assert.deepEqual(published.map(([name]) => name), ['ingress']);
  assert.equal(services.ingress.ports.length, 1);
  // Die Adresse steht fest im Text, nicht in einer Variablen, die .env überschreiben könnte
  assert.match(services.ingress.ports[0], /^127\.0\.0\.1:\$\{MCP_PORT:\?[^}]*\}:3001$/);
  assert.equal(services['gsc-mcp'].environment.MCP_TRUST_PROXY, '${MCP_TRUST_PROXY:-false}');
  assert.deepEqual(services.ingress.networks, ['internal', 'published']);
});

test('Compose mit Caddy: nur Caddy veröffentlicht Ports', async () => {
  const { services } = await compose('docker-compose.yml');
  const published = Object.entries<any>(services).filter(([, s]) => s.ports);
  assert.deepEqual(published.map(([name]) => name), ['caddy']);
  assert.deepEqual(services.caddy.cap_add, ['NET_BIND_SERVICE']);
});

test('Basis-Images per Digest festgelegt', async () => {
  const dockerfile = await readFile(new URL('../Dockerfile', import.meta.url), 'utf8');
  for (const from of dockerfile.match(/^FROM .+$/gm)!) assert.match(from, /@sha256:[0-9a-f]{64}/, from);
  assert.match(dockerfile, /FROM gcr\.io\/distroless\/nodejs24-[a-z0-9]+:nonroot@/);
  for (const file of FILES) {
    for (const [name, service] of Object.entries<any>((await compose(file)).services)) {
      if (service.image && !service.image.startsWith('gsc-mcp:')) assert.match(service.image, /@sha256:[0-9a-f]{64}$/, `${file} ${name}`);
    }
  }
});

test('Workflows: kein pull_request_target, keine Pfadfilter, Actions per Commit-SHA', async () => {
  const dir = new URL('../.github/workflows/', import.meta.url);
  const files = (await readdir(dir)).filter((f) => f.endsWith('.yml'));
  assert.ok(files.length > 0);
  for (const file of files) {
    const text = await readFile(new URL(file, dir), 'utf8');
    const workflow = parse(text);
    assert.ok(!('pull_request_target' in (workflow.on ?? {})), `${file}: pull_request_target`);
    assert.doesNotMatch(text.replace(/#.*$/gm, ''), /pull_request_target/, file);
    for (const trigger of Object.values<any>(workflow.on ?? {})) {
      assert.ok(!trigger?.paths && !trigger?.['paths-ignore'], `${file}: Pfadfilter`);
    }
    for (const uses of text.matchAll(/uses:\s*([^\s#]+)/g)) {
      if (uses[1].startsWith('./')) continue;
      assert.match(uses[1], /@[0-9a-f]{40}$/, `${file}: ${uses[1]} nicht per SHA festgelegt`);
    }
    assert.ok(workflow.permissions, `${file}: permissions fehlen`);
  }
});

test('.gitignore und .dockerignore schließen Schlüssel, Freigaben und .env aus', async () => {
  for (const name of ['.gitignore', '.dockerignore']) {
    const text = await readFile(new URL(`../${name}`, import.meta.url), 'utf8');
    for (const pattern of ['*.json', 'tokens.yaml', '.env', 'secrets']) assert.ok(text.split('\n').some((l) => l.trim().replace(/\/$/, '') === pattern), `${name}: ${pattern}`);
  }
});

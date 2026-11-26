#!/usr/bin/env node
/**
 * gsc-admin: Mandanten, Schlüssel und Tokens verwalten. Läuft als eigener Einmal-Container ohne Netzwerk:
 *
 *   docker compose run --rm -T gsc-admin token list
 *
 * Nur dieser Container darf die Freigabedatei und die Schlüssel schreiben; der Server-Container sieht beides
 * nur lesend. Jede Änderung landet im Audit-Log, nie aber ein Token, ein Hash oder ein Schlüssel.
 */
import { open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { AuditLog } from './audit.ts';
import { count } from './config.ts';
import { parseServiceAccountKey } from './google.ts';
import {
  ConfigError,
  generateToken,
  generateTokenId,
  hashToken,
  propertyProblem,
  readConfigFile,
  TENANT_PATTERN,
  TOKEN_ID_PATTERN,
  USER_PATTERN,
  writeConfigFile,
  type ConfigFile,
} from './tokens.ts';

export interface AdminIo {
  env: NodeJS.ProcessEnv;
  stdin: AsyncIterable<Buffer | string> & { isTTY?: boolean };
  out: (text: string) => void;
  err: (text: string) => void;
}

const USAGE = `gsc-admin – Mandanten und Tokens für gsc-mcp verwalten

  tenant add <mandant>        Mandant anlegen; Schlüssel (JSON des Service Accounts) auf stdin
  tenant key <mandant>        Schlüssel wechseln (gleicher Service Account); JSON auf stdin
  tenant list                 Mandanten mit Service Account und Zahl der Tokens
  tenant remove <mandant>     Mandant und Schlüssel löschen (nur ohne Tokens)

  token add --user <name> --tenant <mandant> --property <p> [--property <p> …]
                              Token anlegen; er wird genau einmal ausgegeben
  token list [--tenant <mandant>]
  token properties <id> --property <p> [--property <p> …]
                              Whitelist eines Tokens ersetzen
  token revoke <id>           Token widerrufen (wirkt nach spätestens einer Sekunde)

  check                       Freigabedatei und Schlüssel prüfen

Properties in exakter Schreibweise der Search Console: sc-domain:example.com oder https://www.example.com/
Beispiel: docker compose run --rm -T gsc-admin tenant add kunde-a < kunde-a.json`;

class UsageError extends Error {}

const MAX_KEY_BYTES = 16 * 1024;
const LOCK_STALE_MS = 60_000;

async function readStdin(io: AdminIo): Promise<string> {
  if (io.stdin.isTTY) throw new UsageError('Den Schlüssel bitte per stdin übergeben, z. B. "… tenant add kunde-a < kunde-a.json" (bei docker compose run mit -T).');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of io.stdin) {
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
    size += buffer.length;
    if (size > MAX_KEY_BYTES) throw new UsageError('Auf stdin kam mehr als ein Service-Account-Schlüssel.');
    chunks.push(buffer);
  }
  if (size === 0) throw new UsageError('Auf stdin kam nichts. Den Schlüssel per "< datei.json" übergeben (bei docker compose run mit -T).');
  return Buffer.concat(chunks).toString('utf8');
}

/** Schreibt eine Datei atomar mit Rechten 0600. */
async function writeSecret(file: string, text: string): Promise<void> {
  const temp = join(dirname(file), `.${randomBytes(4).toString('hex')}.tmp`);
  // Ohne fsync: das Node Permission Model sperrt fsync auf Dateihandles (siehe writeConfigFile)
  await writeFile(temp, text, { flag: 'wx', mode: 0o600 });
  await rename(temp, file).catch(async (error) => {
    await rm(temp, { force: true });
    throw error;
  });
}

/** Verhindert, dass zwei gsc-admin-Aufrufe gleichzeitig dieselbe Datei ändern. */
async function withLock<T>(configFile: string, fn: () => Promise<T>): Promise<T> {
  const lock = join(dirname(configFile), '.gsc-admin.lock');
  const info = await stat(lock).catch(() => undefined);
  if (info && Date.now() - info.mtimeMs > LOCK_STALE_MS) await rm(lock, { force: true });
  let handle;
  try {
    handle = await open(lock, 'wx', 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new UsageError('Ein anderer gsc-admin-Aufruf läuft gerade. Bitte kurz warten.');
    throw error;
  }
  await handle.close();
  try {
    return await fn();
  } finally {
    await rm(lock, { force: true });
  }
}

function checkTenantName(name: string | undefined): string {
  if (!name || !TENANT_PATTERN.test(name)) throw new UsageError('Mandantenname: Kleinbuchstaben, Ziffern und "-", z. B. kunde-a.');
  return name;
}

function checkProperties(values: string[] | undefined): string[] {
  if (!values?.length) throw new UsageError('Mindestens eine --property angeben.');
  for (const value of values) {
    const problem = propertyProblem(value);
    if (problem) throw new UsageError(problem);
  }
  if (new Set(values).size !== values.length) throw new UsageError('Eine Property ist doppelt angegeben.');
  return values;
}

function findToken(config: ConfigFile, id: string | undefined) {
  if (!id || !TOKEN_ID_PATTERN.test(id)) throw new UsageError('Token-ID angeben, z. B. t_0123456789ab (siehe "token list").');
  const token = config.tokens.find((t) => t.id === id);
  if (!token) throw new UsageError(`Token ${id} gibt es nicht.`);
  return token;
}

export async function runAdmin(argv: string[], io: AdminIo): Promise<number> {
  const env = io.env;
  const configFile = env.GSC_CONFIG?.trim() || '/config/tokens.yaml';
  const keyDir = env.GSC_KEY_DIR?.trim() || '/run/secrets/gsc';
  const auditDir = env.GSC_AUDIT_DIR?.trim() || undefined;
  const keyFile = (tenant: string) => join(keyDir, `${tenant}.json`);

  let audit: AuditLog | undefined;
  const record = async (action: string, data: Record<string, unknown>) => {
    if (!audit) return;
    try {
      await audit.admin({ actor: 'gsc-admin', action, ...data });
    } catch (error) {
      io.err(`WARNUNG: Die Änderung ist gespeichert, konnte aber nicht ins Audit-Log geschrieben werden: ${(error as Error).message}\n`);
    }
  };

  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        user: { type: 'string' },
        tenant: { type: 'string' },
        property: { type: 'string', multiple: true },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (error) {
    io.err(`${(error as Error).message}\n\n${USAGE}\n`);
    return 2;
  }
  const { positionals, values } = parsed;
  const [area, command, arg] = positionals;

  if (values.help || !area) {
    io.out(`${USAGE}\n`);
    return 0;
  }

  try {
    // Audit-Log vor jeder Änderung öffnen: ist es nicht beschreibbar, wird nichts geändert
    const changes = !(command === 'list' || area === 'check');
    if (auditDir && changes) audit = await AuditLog.open(auditDir, { retentionDays: count(env, 'GSC_AUDIT_RETENTION_DAYS', 365), prune: false });

    if (area === 'tenant' && command === 'add') {
      const name = checkTenantName(arg);
      const key = parseServiceAccountKey(await readStdin(io));
      await withLock(configFile, async () => {
        const config = await readConfigFile(configFile);
        if (Object.hasOwn(config.tenants, name)) throw new UsageError(`Mandant ${name} gibt es schon. Zum Schlüsselwechsel: tenant key ${name}`);
        const owner = Object.entries(config.tenants).find(([, t]) => t.service_account === key.client_email)?.[0];
        if (owner) throw new UsageError(`Dieser Service Account gehört schon zum Mandanten ${owner}. Jeder Mandant braucht einen eigenen.`);
        await writeSecret(keyFile(name), JSON.stringify({ type: 'service_account', ...key, token_uri: 'https://oauth2.googleapis.com/token' }));
        config.tenants[name] = { service_account: key.client_email };
        await writeConfigFile(configFile, config);
      });
      await record('tenant.add', { tenant: name, serviceAccount: key.client_email, keyId: key.private_key_id.slice(0, 8) });
      io.err(`Mandant ${name} angelegt, Service Account ${key.client_email}.\n`);
      io.err('Diesen Service Account in der Search Console nur bei den Properties des Mandanten eintragen, Berechtigung "Eingeschränkt".\n');
      return 0;
    }

    if (area === 'tenant' && command === 'key') {
      const name = checkTenantName(arg);
      const key = parseServiceAccountKey(await readStdin(io));
      await withLock(configFile, async () => {
        const config = await readConfigFile(configFile);
        const tenant = config.tenants[name];
        if (!tenant || !Object.hasOwn(config.tenants, name)) throw new UsageError(`Mandant ${name} gibt es nicht.`);
        if (tenant.service_account !== key.client_email) {
          throw new UsageError(`Der Schlüssel gehört zu ${key.client_email}, der Mandant ${name} aber zu ${tenant.service_account}. Einen anderen Service Account nur über tenant remove und tenant add.`);
        }
        await writeSecret(keyFile(name), JSON.stringify({ type: 'service_account', ...key, token_uri: 'https://oauth2.googleapis.com/token' }));
      });
      await record('tenant.key', { tenant: name, serviceAccount: key.client_email, keyId: key.private_key_id.slice(0, 8) });
      io.err(`Schlüssel für ${name} ersetzt. Den alten Schlüssel in der Google Cloud Console löschen.\n`);
      return 0;
    }

    if (area === 'tenant' && command === 'list') {
      const config = await readConfigFile(configFile);
      const names = Object.keys(config.tenants).sort();
      if (names.length === 0) io.out('Keine Mandanten.\n');
      for (const name of names) {
        const tokens = config.tokens.filter((t) => t.tenant === name).length;
        const key = await stat(keyFile(name)).then(
          () => 'Schlüssel vorhanden',
          () => 'SCHLÜSSEL FEHLT',
        );
        io.out(`${name}\t${config.tenants[name].service_account}\t${tokens} Token(s)\t${key}\n`);
      }
      return 0;
    }

    if (area === 'tenant' && command === 'remove') {
      const name = checkTenantName(arg);
      await withLock(configFile, async () => {
        const config = await readConfigFile(configFile);
        if (!Object.hasOwn(config.tenants, name)) throw new UsageError(`Mandant ${name} gibt es nicht.`);
        const tokens = config.tokens.filter((t) => t.tenant === name);
        if (tokens.length) throw new UsageError(`Mandant ${name} hat noch ${tokens.length} Token(s): ${tokens.map((t) => t.id).join(', ')}. Erst widerrufen.`);
        delete config.tenants[name];
        await writeConfigFile(configFile, config);
        await rm(keyFile(name), { force: true });
      });
      await record('tenant.remove', { tenant: name });
      io.err(`Mandant ${name} und sein Schlüssel sind gelöscht. Den Service Account in der Search Console und in der Google Cloud Console entfernen.\n`);
      return 0;
    }

    if (area === 'token' && command === 'add') {
      if (arg) throw new UsageError('token add erwartet nur Optionen: --user, --tenant, --property.');
      const user = values.user;
      if (!user || !USER_PATTERN.test(user)) throw new UsageError('--user: Name ohne Leerzeichen, z. B. anna oder anna@example.com (höchstens 64 Zeichen).');
      const tenant = checkTenantName(values.tenant);
      const properties = checkProperties(values.property);
      const token = generateToken();
      const id = generateTokenId();
      await withLock(configFile, async () => {
        const config = await readConfigFile(configFile);
        if (!Object.hasOwn(config.tenants, tenant)) throw new UsageError(`Mandant ${tenant} gibt es nicht. Erst: tenant add ${tenant}`);
        config.tokens.push({ id, user, tenant, properties, token_sha256: hashToken(token), created: new Date().toISOString() });
        await writeConfigFile(configFile, config);
      });
      await record('token.add', { tokenId: id, user, tenant, properties });
      io.err(`Token ${id} für ${user} (Mandant ${tenant}) angelegt. Properties: ${properties.join(', ')}\n`);
      io.err('Der Token wird nur jetzt angezeigt; gespeichert ist nur sein Hash. Sicher an den Nutzer übergeben:\n');
      io.out(`${token}\n`);
      return 0;
    }

    if (area === 'token' && command === 'list') {
      const config = await readConfigFile(configFile);
      const tenant = values.tenant;
      const tokens = config.tokens.filter((t) => !tenant || t.tenant === tenant);
      if (tokens.length === 0) io.out('Keine Tokens.\n');
      for (const t of tokens) io.out(`${t.id}\t${t.user}\t${t.tenant}\t${t.created ?? ''}\t${t.properties.join(' ')}\n`);
      return 0;
    }

    if (area === 'token' && command === 'properties') {
      const properties = checkProperties(values.property);
      let before: string[] = [];
      await withLock(configFile, async () => {
        const config = await readConfigFile(configFile);
        const token = findToken(config, arg);
        before = token.properties;
        token.properties = properties;
        await writeConfigFile(configFile, config);
      });
      await record('token.properties', { tokenId: arg, before, after: properties });
      io.err(`Token ${arg}: Properties jetzt ${properties.join(', ')}\n`);
      return 0;
    }

    if (area === 'token' && command === 'revoke') {
      let removed: { user: string; tenant: string } | undefined;
      await withLock(configFile, async () => {
        const config = await readConfigFile(configFile);
        const token = findToken(config, arg);
        removed = { user: token.user, tenant: token.tenant };
        config.tokens = config.tokens.filter((t) => t.id !== token.id);
        await writeConfigFile(configFile, config);
      });
      await record('token.revoke', { tokenId: arg, ...removed });
      io.err(`Token ${arg} widerrufen.\n`);
      return 0;
    }

    if (area === 'check' && !command) {
      const config = await readConfigFile(configFile);
      let problems = 0;
      for (const [name, tenant] of Object.entries(config.tenants)) {
        try {
          const key = parseServiceAccountKey(await readFile(keyFile(name), 'utf8'));
          if (key.client_email !== tenant.service_account) throw new Error('Schlüssel gehört zu einem anderen Service Account');
          io.out(`ok     Mandant ${name}: Schlüssel passt zu ${tenant.service_account}\n`);
        } catch (error) {
          problems += 1;
          io.out(`FEHLER Mandant ${name}: ${(error as NodeJS.ErrnoException).code === 'ENOENT' ? 'Schlüssel fehlt' : (error as Error).message}\n`);
        }
      }
      io.out(`ok     ${config.tokens.length} Token(s), ${Object.keys(config.tenants).length} Mandant(en) in ${configFile}\n`);
      return problems ? 1 : 0;
    }

    throw new UsageError(`Unbekannter Befehl: ${positionals.join(' ')}\n\n${USAGE}`);
  } catch (error) {
    if (error instanceof UsageError || error instanceof ConfigError) {
      io.err(`${error.message}\n`);
      return 2;
    }
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'EROFS' || code === 'EACCES' || code === 'EPERM' || code === 'ERR_ACCESS_DENIED') {
      const resource = (error as { resource?: string }).resource;
      io.err(`Keine Schreibrechte (${code}${resource ? `: ${resource}` : ''}). gsc-admin läuft als eigener Container: docker compose run --rm -T gsc-admin …\n`);
      return 1;
    }
    io.err(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  } finally {
    audit?.close();
  }
}

if (import.meta.main) {
  runAdmin(process.argv.slice(2), {
    env: process.env,
    stdin: process.stdin,
    out: (text) => process.stdout.write(text),
    err: (text) => process.stderr.write(text),
  }).then(
    (code) => process.exit(code),
    (error: unknown) => {
      console.error(error instanceof Error ? error.message : error);
      process.exit(2);
    },
  );
}

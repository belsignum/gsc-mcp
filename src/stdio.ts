#!/usr/bin/env node
/**
 * Lokaler Start über stdio, für Tests mit einem eigenen Schlüssel auf dem eigenen Rechner.
 * Der MCP-Client startet diesen Prozess selbst; es gibt keine Tokens, nur einen Schlüssel und eine Whitelist.
 *
 *   GSC_KEY_FILE    Pfad zur JSON-Schlüsseldatei des Service Accounts (Pflicht)
 *   GSC_PROPERTIES  freigegebene Properties, kommagetrennt, exakte Schreibweise (Pflicht)
 *   GSC_AUDIT_DIR   optional: Audit-Log schreiben
 */
import { readFile } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { AuditLog } from './audit.ts';
import { Budget } from './budget.ts';
import { loadConfig } from './config.ts';
import { GoogleClients, parseServiceAccountKey } from './google.ts';
import { createGscServer } from './server.ts';
import { propertyProblem } from './tokens.ts';

async function main(): Promise<void> {
  const config = loadConfig();
  const keyFile = process.env.GSC_KEY_FILE?.trim();
  if (!keyFile) throw new Error('GSC_KEY_FILE fehlt (Pfad zur JSON-Schlüsseldatei des Service Accounts).');
  const properties = (process.env.GSC_PROPERTIES ?? '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (properties.length === 0) throw new Error('GSC_PROPERTIES fehlt (freigegebene Properties, kommagetrennt, z. B. sc-domain:example.com).');
  for (const property of properties) {
    const problem = propertyProblem(property);
    if (problem) throw new Error(`GSC_PROPERTIES: ${problem}`);
  }
  const key = parseServiceAccountKey(await readFile(keyFile, 'utf8'));
  const tenant = { name: 'local', serviceAccount: key.client_email };
  const google = new GoogleClients({ keyDir: '', keyFile: () => keyFile, proxy: config.egressProxy });
  const audit = config.auditDir ? await AuditLog.open(config.auditDir, { retentionDays: config.auditRetentionDays, maxBytes: config.auditMaxBytes }) : undefined;
  const inspections = new Budget(config.maxInspectionsPerDay);
  const identity = { tokenId: 'local', user: userInfo().username || 'local', tenant: tenant.name, properties: Object.freeze(properties) };

  serveStdio(() => createGscServer({ identity, tenant, google, audit, inspections }), {
    onerror: (error) => console.error('[gsc-mcp]', error.message),
  });
}

main().catch((error: unknown) => {
  // stdout gehört dem MCP-Protokoll, Meldungen daher nur auf stderr
  console.error('[gsc-mcp]', error instanceof Error ? error.message : error);
  process.exit(1);
});

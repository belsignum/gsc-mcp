/**
 * Die MCP-Tools. Alle lesen nur.
 *
 * Jedes Tool mit Property prüft sie zuerst exakt gegen die Whitelist des Tokens. Ist sie nicht freigegeben,
 * geht keine Anfrage an Google, und die Antwort ist dieselbe wie für eine Property, die es nicht gibt oder
 * auf die der Service Account des Mandanten keinen Zugriff hat (NOT_AVAILABLE).
 */
import * as z from 'zod';
import type { McpServer } from '@modelcontextprotocol/server';
import type { AuditLog, AuditResult } from './audit.ts';
import { BudgetError, type Budget } from './budget.ts';
import { GoogleError, type GoogleClients, type TenantApi } from './google.ts';
import type { Identity, Tenant } from './tokens.ts';

export interface ToolContext {
  server: McpServer;
  identity: Identity;
  /** Mandant laut Freigabedatei zum Zeitpunkt des Requests (undefined: inzwischen entfernt) */
  tenant: Tenant | undefined;
  google: GoogleClients;
  /** Ohne Audit-Log (nur beim lokalen stdio-Start) wird nichts protokolliert. */
  audit: AuditLog | undefined;
  /** URL-Prüfungen je Mandant und Tag */
  inspections: Budget;
}

type TextResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };

export const NOT_AVAILABLE_TEXT = 'Property nicht verfügbar. Mit gsc_list_properties siehst du, welche Properties du abfragen kannst.';

/** Die eine Antwort für "nicht freigegeben", "gibt es nicht" und "Google verweigert den Zugriff". */
function notAvailable(): TextResult {
  return { content: [{ type: 'text', text: NOT_AVAILABLE_TEXT }], isError: true };
}

function ok(data: unknown): TextResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 1) }] };
}

function fail(message: string): TextResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/** Fehler, die der Server selbst feststellt (Limit, URL außerhalb der Property). Die Meldung geht an den Nutzer. */
class LocalError extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.reason = reason;
  }
}

const AUDIT_FAILED = 'Der Aufruf konnte nicht protokolliert werden. Ohne Protokoll gibt der Server keine Daten heraus. Bitte den Betreiber des Servers informieren.';

/**
 * Führt einen Tool-Aufruf aus: Whitelist prüfen, Google fragen, protokollieren.
 * Daten gehen nur an den Client, wenn der Aufruf protokolliert ist.
 */
async function call(
  ctx: ToolContext,
  tool: string,
  property: string | undefined,
  params: Record<string, unknown>,
  fn: (api: TenantApi | undefined) => Promise<{ data: unknown; rows?: number }>,
  options: { google?: boolean } = {},
): Promise<TextResult> {
  const started = performance.now();
  const base = { user: ctx.identity.user, tenant: ctx.identity.tenant, tokenId: ctx.identity.tokenId, tool, property, params };
  const log = (result: AuditResult, extra: { reason?: string; detail?: string; rows?: number } = {}) =>
    ctx.audit ? ctx.audit.call({ ...base, result, ...extra, ms: Math.round(performance.now() - started) }) : Promise.resolve();

  if (ctx.audit?.full) return fail(AUDIT_FAILED);

  if (property !== undefined && !ctx.identity.properties.includes(property)) {
    await log('denied', { reason: 'whitelist' }).catch(() => {});
    return notAvailable();
  }

  let outcome: { data: unknown; rows?: number };
  try {
    let api: TenantApi | undefined;
    if (options.google !== false) {
      if (!ctx.tenant) throw new GoogleError('setup', 'Der Google-Zugang deines Mandanten ist nicht eingerichtet. Bitte den Betreiber des Servers informieren.', 'Mandant fehlt in der Freigabedatei');
      api = await ctx.google.forTenant(ctx.tenant);
    }
    outcome = await fn(api);
  } catch (error) {
    if (error instanceof GoogleError && error.kind === 'denied') {
      await log('denied', { reason: `google_${error.status ?? 'denied'}`, detail: error.detail }).catch(() => {});
      return notAvailable();
    }
    if (error instanceof LocalError) {
      await log('denied', { reason: error.reason }).catch(() => {});
      return fail(error.message);
    }
    if (error instanceof BudgetError) {
      await log('denied', { reason: 'limit' }).catch(() => {});
      return fail(error.message);
    }
    if (error instanceof GoogleError) {
      await log('error', { reason: error.kind, detail: error.detail }).catch(() => {});
      return fail(error.message);
    }
    await log('error', { reason: 'internal', detail: error instanceof Error ? error.message : String(error) }).catch(() => {});
    return fail('Interner Fehler.');
  }

  try {
    await log('ok', { rows: outcome.rows });
  } catch {
    return fail(AUDIT_FAILED);
  }
  return ok(outcome.data);
}

// ---- Argumente --------------------------------------------------------------

const READ = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

const propertyArg = z
  .string()
  .min(1)
  .max(512)
  .describe('Freigegebene Property in exakter Schreibweise der Search Console, z. B. "sc-domain:example.com" oder "https://www.example.com/". gsc_list_properties zeigt sie.');

function isCalendarDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return false;
  const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
  return date.toISOString().startsWith(value);
}

const dateArg = (description: string) =>
  z
    .string()
    .refine(isCalendarDate, 'Erwartet wird ein Datum im Format YYYY-MM-DD.')
    .describe(description);

const DIMENSIONS = ['query', 'page', 'country', 'device', 'date', 'searchAppearance', 'hour'] as const;
const FILTER_DIMENSIONS = ['query', 'page', 'country', 'device', 'searchAppearance'] as const;
const OPERATORS = ['equals', 'notEquals', 'contains', 'notContains', 'includingRegex', 'excludingRegex'] as const;
const SEARCH_TYPES = ['web', 'image', 'video', 'news', 'discover', 'googleNews'] as const;
export const MAX_ROWS = 5000;
const DEFAULT_ROWS = 1000;

const httpUrlArg = (description: string) =>
  z
    .string()
    .max(2048)
    .refine((value) => {
      try {
        const url = new URL(value);
        return (url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password;
      } catch {
        return false;
      }
    }, 'Erwartet wird eine vollständige http(s)-URL.')
    .describe(description);

/** Gehört die URL zur Property? Domain-Property: Domain und alle Subdomains; URL-Präfix: beginnt mit dem Präfix. */
export function urlInProperty(value: string, property: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
  if (property.startsWith('sc-domain:')) {
    const domain = property.slice('sc-domain:'.length);
    return url.hostname === domain || url.hostname.endsWith(`.${domain}`);
  }
  return url.href.startsWith(property);
}

function round(value: number | null | undefined, digits: number): number | undefined {
  return typeof value === 'number' ? Number(value.toFixed(digits)) : undefined;
}

// ---- Tools ------------------------------------------------------------------

export function registerTools(ctx: ToolContext): void {
  const { server } = ctx;

  server.registerTool(
    'gsc_whoami',
    {
      title: 'Eigener Zugang',
      description: 'Zeigt Nutzer, Mandant und die Properties, die dieser Token abfragen darf. Fragt Google nicht.',
      annotations: { ...READ, openWorldHint: false },
    },
    () =>
      call(ctx, 'gsc_whoami', undefined, {}, async () => ({ data: { user: ctx.identity.user, tenant: ctx.identity.tenant, properties: ctx.identity.properties } }), {
        google: false,
      }),
  );

  server.registerTool(
    'gsc_list_properties',
    {
      title: 'Properties auflisten',
      description: 'Listet die Properties, die dieser Token abfragen darf und auf die der Service Account des Mandanten bei Google Zugriff hat, mit Berechtigungsstufe.',
      annotations: READ,
    },
    () =>
      call(ctx, 'gsc_list_properties', undefined, {}, async (api) => {
        const sites = (await api!.listSites()).siteEntry ?? [];
        const properties = sites
          .filter((site) => typeof site.siteUrl === 'string' && ctx.identity.properties.includes(site.siteUrl))
          .map((site) => ({ property: site.siteUrl, permissionLevel: site.permissionLevel }));
        return { data: { count: properties.length, properties }, rows: properties.length };
      }),
  );

  server.registerTool(
    'gsc_search_analytics',
    {
      title: 'Suchanalyse',
      description:
        'Leistungsdaten der Google-Suche (Klicks, Impressionen, CTR, Position) für einen Zeitraum, gruppiert nach Dimensionen. Entspricht dem Leistungsbericht der Search Console. Daten liegen meist 2–3 Tage zurück; Datumsgrenzen gelten in Pacific Time.',
      inputSchema: z.object({
        property: propertyArg,
        startDate: dateArg('Erster Tag (YYYY-MM-DD), einschließlich.'),
        endDate: dateArg('Letzter Tag (YYYY-MM-DD), einschließlich.'),
        dimensions: z
          .array(z.enum(DIMENSIONS))
          .max(DIMENSIONS.length)
          .refine((list) => new Set(list).size === list.length, 'Jede Dimension nur einmal angeben.')
          .optional()
          .describe('Gruppierung, z. B. ["query"] oder ["page","device"]. Ohne Angabe: Summe über den Zeitraum. "hour" nur mit dataState "hourly_all".'),
        type: z.enum(SEARCH_TYPES).optional().describe('Suchtyp (Standard web). "discover" und "googleNews" kennen keine Dimension "query".'),
        filters: z
          .array(
            z.object({
              dimension: z.enum(FILTER_DIMENSIONS),
              operator: z.enum(OPERATORS).optional().describe('Standard equals. Regex in RE2-Syntax.'),
              expression: z.string().min(1).max(4096).describe('Vergleichswert, bei country der ISO-3166-1-alpha-3-Code (z. B. "deu"), bei device DESKTOP, MOBILE oder TABLET.'),
            }),
          )
          .max(20)
          .optional()
          .describe('Filter, alle müssen zutreffen (UND).'),
        aggregationType: z.enum(['auto', 'byPage', 'byProperty', 'byNewsShowcasePanel']).optional().describe('Zusammenfassung nach Seite oder Property (Standard auto).'),
        dataState: z.enum(['final', 'all', 'hourly_all']).optional().describe('"all" schließt noch nicht endgültige, frische Daten ein (Standard final).'),
        rowLimit: z.number().int().min(1).max(MAX_ROWS).optional().describe(`Höchstzahl Zeilen (Standard ${DEFAULT_ROWS}, max. ${MAX_ROWS}).`),
        startRow: z.number().int().min(0).max(1_000_000).optional().describe('Erste Zeile (0-basiert) zum Blättern.'),
      }),
      annotations: READ,
    },
    (input) => {
      const rowLimit = input.rowLimit ?? DEFAULT_ROWS;
      const params = {
        startDate: input.startDate,
        endDate: input.endDate,
        dimensions: input.dimensions,
        type: input.type,
        filters: input.filters,
        aggregationType: input.aggregationType,
        dataState: input.dataState,
        rowLimit,
        startRow: input.startRow,
      };
      return call(ctx, 'gsc_search_analytics', input.property, params, async (api) => {
        if (input.startDate > input.endDate) throw new LocalError('invalid', 'startDate liegt nach endDate.');
        const dimensions = input.dimensions ?? [];
        const response = await api!.query(input.property, {
          startDate: input.startDate,
          endDate: input.endDate,
          dimensions,
          type: input.type,
          dimensionFilterGroups: input.filters?.length
            ? [{ groupType: 'and', filters: input.filters.map((f) => ({ dimension: f.dimension, operator: f.operator ?? 'equals', expression: f.expression })) }]
            : undefined,
          aggregationType: input.aggregationType,
          dataState: input.dataState,
          rowLimit,
          startRow: input.startRow,
        });
        const rows = (response.rows ?? []).map((row) => {
          const out: Record<string, unknown> = {};
          dimensions.forEach((dimension, i) => (out[dimension] = row.keys?.[i]));
          out.clicks = row.clicks;
          out.impressions = row.impressions;
          out.ctr = round(row.ctr, 4);
          out.position = round(row.position, 2);
          return out;
        });
        return {
          data: {
            property: input.property,
            startDate: input.startDate,
            endDate: input.endDate,
            type: input.type ?? 'web',
            dimensions,
            aggregation: response.responseAggregationType,
            count: rows.length,
            hasMore: rows.length === rowLimit,
            rows,
          },
          rows: rows.length,
        };
      });
    },
  );

  server.registerTool(
    'gsc_list_sitemaps',
    {
      title: 'Sitemaps auflisten',
      description: 'Listet die eingereichten Sitemaps einer Property mit Status, Fehlern, Warnungen und Anzahl der URLs.',
      inputSchema: z.object({
        property: propertyArg,
        sitemapIndex: httpUrlArg('Optional: nur Sitemaps aus diesem Sitemap-Index.').optional(),
      }),
      annotations: READ,
    },
    (input) =>
      call(ctx, 'gsc_list_sitemaps', input.property, { sitemapIndex: input.sitemapIndex }, async (api) => {
        const sitemaps = (await api!.listSitemaps(input.property, input.sitemapIndex)).sitemap ?? [];
        return { data: { property: input.property, count: sitemaps.length, sitemaps }, rows: sitemaps.length };
      }),
  );

  server.registerTool(
    'gsc_get_sitemap',
    {
      title: 'Sitemap lesen',
      description: 'Details zu einer eingereichten Sitemap: zuletzt eingereicht und abgerufen, Fehler, Warnungen, Inhalte.',
      inputSchema: z.object({
        property: propertyArg,
        feedpath: httpUrlArg('Vollständige URL der Sitemap, z. B. https://www.example.com/sitemap.xml.'),
      }),
      annotations: READ,
    },
    (input) =>
      call(ctx, 'gsc_get_sitemap', input.property, { feedpath: input.feedpath }, async (api) => ({
        data: await api!.getSitemap(input.property, input.feedpath),
        rows: 1,
      })),
  );

  server.registerTool(
    'gsc_inspect_url',
    {
      title: 'URL prüfen',
      description:
        'Index-Status einer URL bei Google (wie die URL-Prüfung der Search Console): indexiert oder nicht, Grund, kanonische URL, letzter Crawl, Rich Results. Die URL muss zur Property gehören.' +
        (ctx.inspections.max > 0 ? ` Höchstens ${ctx.inspections.max} Prüfungen pro Tag und Mandant.` : ''),
      inputSchema: z.object({
        property: propertyArg,
        url: httpUrlArg('Vollständige URL einer Seite dieser Property.'),
        languageCode: z
          .string()
          .regex(/^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$/, 'Erwartet wird ein Sprachcode wie "de" oder "en-US".')
          .optional()
          .describe('Sprache der Meldungen (BCP-47, z. B. "de"). Standard en-US.'),
      }),
      annotations: READ,
    },
    (input) =>
      call(ctx, 'gsc_inspect_url', input.property, { url: input.url, languageCode: input.languageCode }, async (api) => {
        if (!urlInProperty(input.url, input.property)) throw new LocalError('url_outside_property', 'Die URL gehört nicht zu dieser Property.');
        ctx.inspections.take(ctx.identity.tenant);
        const response = await api!.inspect(input.property, input.url, input.languageCode);
        return { data: { property: input.property, url: input.url, ...response.inspectionResult }, rows: 1 };
      }),
  );
}

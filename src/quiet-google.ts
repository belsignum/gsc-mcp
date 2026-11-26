/**
 * Muss vor den Google-Bibliotheken geladen werden (erster Import in google.ts): google-logging-utils liest
 * GOOGLE_SDK_NODE_LOGGING schon beim Import. Ist die Variable gesetzt, schreiben google-auth-library und gaxios
 * Access Tokens und signierte JWTs ins Log (nachgestellt). Sie bleibt deshalb immer aus.
 */
if (process.env.GOOGLE_SDK_NODE_LOGGING !== undefined) {
  delete process.env.GOOGLE_SDK_NODE_LOGGING;
  console.error('[gsc-mcp] GOOGLE_SDK_NODE_LOGGING wird ignoriert: das Debug-Logging würde Access Tokens ins Log schreiben.');
}

export {};

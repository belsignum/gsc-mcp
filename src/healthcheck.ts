#!/usr/bin/env node
/**
 * Healthcheck für Docker. Das Laufzeit-Image hat weder Shell noch wget/curl; geprüft wird deshalb mit Node.
 * Aufruf: node dist/healthcheck.js [url]   (Standard http://127.0.0.1:3000/health)
 */
export {};

const url = process.argv[2] ?? 'http://127.0.0.1:3000/health';
try {
  const response = await fetch(url, { signal: AbortSignal.timeout(4000), redirect: 'error' });
  process.exit(response.status === 200 ? 0 : 1);
} catch {
  process.exit(1);
}

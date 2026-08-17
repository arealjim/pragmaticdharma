#!/usr/bin/env node
// Regenerates the [[secrets_store_secrets]] block in wrangler.toml from the
// project registry (src/registry.js / projects.config.mjs). TOML can't
// import JS, so this is the one site that still needs codegen instead of a
// runtime import. `npm run deploy` runs this, then fails the deploy if it
// produced a diff — a hand-edit inside the generated block means the
// registry is out of sync, not that the TOML is wrong. See
// docs/design-v2-registry.md (Slice 2) and docs/v2-registry-schema.md.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { KID_TO_BINDING } from '../src/registry.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const WRANGLER_PATH = join(__dirname, '..', 'wrangler.toml');
export const STORE_ID = '626a023faf5e4be98729d2f4b9849f09';
export const BEGIN_MARKER = '# --- BEGIN GENERATED SECRETS (gen-wrangler.mjs) ---';
export const END_MARKER = '# --- END GENERATED SECRETS ---';

function secretBlock(binding, secretName) {
  return `[[secrets_store_secrets]]\nbinding     = "${binding}"\nstore_id    = "${STORE_ID}"\nsecret_name = "${secretName}"`;
}

// Order: platform signing key first (it signs the initial session JWT),
// then the Resend key (not registry-derived — the platform's own outbound
// email key), then per-project JWT keys in registry order. kidBindingOverride
// entries (sentinel, boardreview today) collapse into the binding they
// share, so they add no block of their own.
export function generatedBlock() {
  const seen = new Set();
  const entries = [];
  entries.push(['JWT_SECRET_PRAGMATICDHARMA', 'JWT_SECRET_PRAGMATICDHARMA']);
  seen.add('JWT_SECRET_PRAGMATICDHARMA');
  entries.push(['RESEND_API_KEY', 'PRAGMATICDHARMA_RESEND_API_KEY']);
  for (const binding of Object.values(KID_TO_BINDING)) {
    if (seen.has(binding)) continue;
    seen.add(binding);
    entries.push([binding, binding]);
  }
  return entries.map(([binding, secretName]) => secretBlock(binding, secretName)).join('\n\n');
}

export function withGeneratedBlock(toml) {
  const beginIdx = toml.indexOf(BEGIN_MARKER);
  const endIdx = toml.indexOf(END_MARKER);
  if (beginIdx === -1 || endIdx === -1) {
    throw new Error(`gen-wrangler: markers not found in wrangler.toml ("${BEGIN_MARKER}" / "${END_MARKER}")`);
  }
  const before = toml.slice(0, beginIdx + BEGIN_MARKER.length);
  const after = toml.slice(endIdx);
  return `${before}\n${generatedBlock()}\n\n${after}`;
}

function main() {
  const toml = readFileSync(WRANGLER_PATH, 'utf8');
  const next = withGeneratedBlock(toml);
  if (next === toml) {
    console.log('gen-wrangler: wrangler.toml already up to date');
    return;
  }
  writeFileSync(WRANGLER_PATH, next);
  console.log('gen-wrangler: wrangler.toml regenerated');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

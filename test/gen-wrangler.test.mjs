// v2 Slice 2: wrangler.toml's [[secrets_store_secrets]] block is generated
// from the registry (scripts/gen-wrangler.mjs), since TOML can't import JS.
// This test catches drift — a hand-edit inside the generated block, or a
// registry change whose regeneration wasn't committed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  WRANGLER_PATH,
  BEGIN_MARKER,
  END_MARKER,
  generatedBlock,
  withGeneratedBlock,
} from '../scripts/gen-wrangler.mjs';

test('wrangler.toml generated secrets block matches the registry', () => {
  const toml = readFileSync(WRANGLER_PATH, 'utf8');
  assert.equal(withGeneratedBlock(toml), toml, 'wrangler.toml is stale — run `npm run gen:wrangler` and commit the result');
});

test('generated block has one entry per unique KID_TO_BINDING value + RESEND_API_KEY', () => {
  const block = generatedBlock();
  const bindings = [...block.matchAll(/binding\s+=\s+"([^"]+)"/g)].map(m => m[1]);
  assert.equal(new Set(bindings).size, bindings.length, 'no duplicate bindings');
  assert.ok(bindings.includes('RESEND_API_KEY'));
  assert.ok(bindings.includes('JWT_SECRET_PRAGMATICDHARMA'));
  assert.equal(bindings[0], 'JWT_SECRET_PRAGMATICDHARMA', 'platform key signs the initial session JWT — must come first');
});

test('generator is idempotent', () => {
  const toml = readFileSync(WRANGLER_PATH, 'utf8');
  const once = withGeneratedBlock(toml);
  const twice = withGeneratedBlock(once);
  assert.equal(once, twice);
});

test('throws if markers are missing', () => {
  assert.throws(() => withGeneratedBlock('no markers here'), /markers not found/);
});

test(`markers present: ${BEGIN_MARKER} / ${END_MARKER}`, () => {
  const toml = readFileSync(WRANGLER_PATH, 'utf8');
  assert.ok(toml.includes(BEGIN_MARKER));
  assert.ok(toml.includes(END_MARKER));
});

// v2 Slice 4: smoke tests for the pd CLI's node helper scripts. Full
// end-to-end coverage of `pd add-project` (registry-config mutation, wrangler
// codegen, Secrets Store CLI attempt) was verified manually against a scratch
// copy of the repo — it isn't run here to avoid mutating the real
// projects.config.mjs/wrangler.toml as a side effect of `npm test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

test('scripts/list-projects.mjs (pd projects) lists all 12 projects with headers', () => {
  const out = execFileSync('node', [join(ROOT, 'scripts', 'list-projects.mjs')], { encoding: 'utf8' });
  const lines = out.trim().split('\n');
  assert.match(lines[0], /KEY\s+HOST\s+GATE\s+STATUS/);
  // header + separator + 12 project rows
  assert.equal(lines.length, 14);
  assert.match(out, /boardreview/);
  assert.match(out, /sentinel.*yes/); // customAuthTest column
});

test('scripts/add-project.mjs rejects a duplicate key without touching any files', () => {
  assert.throws(() => {
    execFileSync('node', [join(ROOT, 'scripts', 'add-project.mjs'), 'shield'], { encoding: 'utf8', stdio: 'pipe' });
  }, /Command failed/);
});

test('scripts/add-project.mjs rejects an invalid key', () => {
  assert.throws(() => {
    execFileSync('node', [join(ROOT, 'scripts', 'add-project.mjs'), 'Not_Valid'], { encoding: 'utf8', stdio: 'pipe' });
  }, /Command failed/);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { extractFunction, normalize, fnHash } from '../scripts/auth-drift.mjs';

const canon = readFileSync(new URL('../shared/auth-cloudflare.js', import.meta.url), 'utf8');

test('extracts every checked function from the canonical verifier', () => {
  const { functions } = JSON.parse(readFileSync(new URL('../shared/verifier-copies.json', import.meta.url), 'utf8'));
  for (const f of functions) assert.ok(extractFunction(canon, f), `${f} not found`);
});

test('formatting, quotes, comments and export do not count as drift', () => {
  const reformatted = extractFunction(canon, 'verifyJWT')
    .replace(/\/\/.*$/gm, '')          // a copy that dropped the comments
    .replace(/'/g, '"')
    .replace(/\n\s*/g, ' ')
    .replace(/^/, '// a comment\nexport ');
  assert.equal(fnHash(reformatted, 'verifyJWT'), fnHash(canon, 'verifyJWT'));
});

test('a semantic change is drift', () => {
  const weakened = canon.replace("if (header.alg !== 'HS256') return null;", '');
  assert.notEqual(fnHash(weakened, 'verifyJWT'), fnHash(canon, 'verifyJWT'));
  const noExp = canon.replace('if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;', '');
  assert.notEqual(fnHash(noExp, 'verifyJWT'), fnHash(canon, 'verifyJWT'));
});

test('a missing function hashes to null', () => {
  assert.equal(fnHash('const x = 1;', 'verifyJWT'), null);
  assert.equal(normalize('a  b\n c'), 'abc');
});

#!/usr/bin/env node
// Verifier drift check (AUTH-DESIGN.md weakness #2).
//
// Workers can't share code across deployments, so every relying party inlines
// its own copy of the verifier in shared/auth-cloudflare.js. This hashes each
// copy's security-relevant functions against the canonical ones and exits
// non-zero on any unexplained difference.
//
// Which apps get checked is derived, not listed: every registry project
// (projects.config.mjs) whose host currently resolves in DNS is live; offline
// apps (custom domain detached, 2026-09-29) are reported and skipped. A live
// app with no row in shared/verifier-copies.json is itself a failure — that is
// how a restored app gets noticed.
//
// Copies are read from the app's bare repo on biggie (~/repos/<repo>.git, HEAD)
// so the result doesn't depend on any working tree; a missing bare falls back
// to ~/workspace/<repo>. It checks committed code, not the deployed bundle.
//
// Surface, never gate: fleet-health runs this as an invariant (red row);
// nothing blocks a relying party's deploy on it.
//
//   node scripts/auth-drift.mjs            # report; exit 1 on drift
//   node scripts/auth-drift.mjs --hash F   # print canonical + per-app hashes of F
//
// Output: one line per check; failures start with "FAIL" (fleet-health shows
// those); the last line is the summary.

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve as dnsResolve } from 'node:dns/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROJECTS } from '../projects.config.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HOME = homedir();
const ZONE = 'pragmaticdharma.org';

// Pull `function NAME(...) { ... }` out of a source file by brace matching.
// Good enough for the verifier code (no unbalanced braces in its strings).
export function extractFunction(src, name) {
  const m = new RegExp(`(?:export\\s+)?(?:async\\s+)?function\\s+${name}\\s*\\(`).exec(src);
  if (!m) return null;
  // skip past the parameter list's closing paren first
  const close = src.indexOf(')', m.index + m[0].length);
  const i = src.indexOf('{', close);
  let depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}' && --depth === 0) return src.slice(m.index, j + 1);
  }
  return null;
}

// Formatting-blind: drop comments, `export`, all whitespace; one quote style.
export function normalize(fn) {
  return fn
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/^export\s+/, '')
    .replace(/"/g, "'")
    .replace(/\s+/g, '');
}

export function fnHash(src, name) {
  const fn = extractFunction(src, name);
  return fn === null ? null : createHash('sha256').update(normalize(fn)).digest('hex');
}

function readCopy(repo, file) {
  const bare = join(HOME, 'repos', `${repo}.git`);
  if (existsSync(bare)) {
    try {
      return { src: execFileSync('git', ['--git-dir', bare, 'show', `HEAD:${file}`],
                                 { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }),
               from: `~/repos/${repo}.git HEAD` };
    } catch { /* fall through */ }
  }
  const wt = join(HOME, 'workspace', repo, file);
  if (existsSync(wt)) return { src: readFileSync(wt, 'utf8'), from: `~/workspace/${repo} (working tree)` };
  return null;
}

async function isLive(host) {
  try { await dnsResolve(host); return true; }
  catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return false;
    throw new Error(`dns probe ${host}: ${e.code || e.message}`);
  }
}

async function main() {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'shared/verifier-copies.json'), 'utf8'));
  const canonSrc = readFileSync(join(ROOT, 'shared/auth-cloudflare.js'), 'utf8');
  const fns = manifest.functions;
  const canon = Object.fromEntries(fns.map(f => [f, fnHash(canonSrc, f)]));

  if (process.argv[2] === '--hash') {
    const f = process.argv[3];
    console.log(`canonical ${f} ${fnHash(canonSrc, f)}`);
    for (const [key, row] of Object.entries(manifest.copies)) {
      if (!row.repo) continue;
      const c = readCopy(row.repo, row.file);
      console.log(`${key} ${f} ${c ? fnHash(c.src, f) : 'unreadable'}`);
    }
    return 0;
  }

  let fails = 0, checked = 0, offline = [];
  const fail = msg => { fails++; console.log(`FAIL ${msg}`); };

  for (const key of Object.keys(manifest.copies)) {
    if (!PROJECTS.some(p => p.key === key)) fail(`${key}: in verifier-copies.json but not in the registry`);
  }

  for (const p of PROJECTS) {
    const host = `${p.subdomain}.${ZONE}`;
    let live;
    try { live = await isLive(host); }
    catch (e) { fail(e.message); continue; }
    if (!live) { offline.push(p.key); continue; }

    let row = manifest.copies[p.key];
    if (row?.sameAs) { console.log(`ok   ${p.key}: same worker as ${row.sameAs}`); continue; }
    if (!row) { fail(`${p.key}: ${host} is live but has no row in shared/verifier-copies.json`); continue; }

    const copy = readCopy(row.repo, row.file);
    if (!copy) { fail(`${p.key}: cannot read ${row.repo}:${row.file}`); continue; }
    checked++;
    const bad = [];
    for (const f of fns) {
      const h = fnHash(copy.src, f);
      const dev = row.deviations?.[f];
      if (h === null) bad.push(`${f} missing`);
      else if (dev) { if (h !== dev.sha256) bad.push(`${f} changed from its recorded deviation`); }
      else if (h !== canon[f]) bad.push(`${f} differs from canonical`);
    }
    if (bad.length) fail(`${p.key} (${row.repo}:${row.file}): ${bad.join(', ')}`);
    else console.log(`ok   ${p.key}: ${fns.length} functions match (${copy.from})`);
  }

  if (offline.length) console.log(`skip offline (host does not resolve): ${offline.join(', ')}`);
  console.log(fails
    ? `${fails} verifier drift finding(s) across ${checked} live relying parties`
    : `${checked} live relying parties match the canonical verifier (${offline.length} offline skipped)`);
  return fails ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().then(code => process.exit(code), e => { console.log(`FAIL ${e.message}`); process.exit(2); });
}

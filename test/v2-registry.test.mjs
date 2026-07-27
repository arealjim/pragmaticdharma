// Registry derivation tests. worker.js imports these structures directly from
// src/registry.js (as of slice 1) rather than defining its own literals, so
// these assert shape/size against the registry itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  KNOWN_PROJECTS,
  REDIRECT_ALLOWLIST,
  KID_TO_BINDING,
  HOST_TO_PROJECT,
  CSP_CONNECT_SRC_HOSTS,
} from '../src/registry.js';

test('KNOWN_PROJECTS has one entry per project', () => {
  assert.equal(KNOWN_PROJECTS.length, 12, 'expected 12 project keys');
  assert.deepStrictEqual(KNOWN_PROJECTS, [
    'health', 'shield', 'ego-assessment', 'mindreader', 'psychtools',
    'astrology', 'practice', 'sentinel', 'bromnichord', 'discern', 'review',
    'boardreview',
  ]);
});

test('REDIRECT_ALLOWLIST has 14 hosts (12 projects + apex + retreats)', () => {
  assert.equal(REDIRECT_ALLOWLIST.size, 14, 'allowlist must have exactly 14 hosts');
  assert.ok(REDIRECT_ALLOWLIST.has('pragmaticdharma.org'));
  assert.ok(REDIRECT_ALLOWLIST.has('retreats.pragmaticdharma.org'));
  assert.ok(REDIRECT_ALLOWLIST.has('psychology.pragmaticdharma.org'));
  assert.ok(REDIRECT_ALLOWLIST.has('boardreview.pragmaticdharma.org'), 'board mirror must be allow-listed');
});

test('HOST_TO_PROJECT has 12 entries; boardreview is its own project, not a review alias', () => {
  assert.equal(Object.keys(HOST_TO_PROJECT).length, 12, 'host map must have exactly 12 entries');
  assert.equal(HOST_TO_PROJECT['psychology.pragmaticdharma.org'], 'ego-assessment');
  // boardreview.* is its own least-privilege project claim (2026-07-27 hardening,
  // todo-board card 5d077131052f) — it no longer resolves to 'review'.
  assert.equal(HOST_TO_PROJECT['boardreview.pragmaticdharma.org'], 'boardreview');
  // ...but its kid still verifies against the same JWT_SECRET_REVIEW binding as
  // 'review' via kidBindingOverride — no new Secrets Store secret was needed.
  assert.equal(KID_TO_BINDING[HOST_TO_PROJECT['boardreview.pragmaticdharma.org']], 'JWT_SECRET_REVIEW');
});

test('KID_TO_BINDING has 13 entries (12 projects + platform); boardreview reuses the review secret', () => {
  assert.equal(Object.keys(KID_TO_BINDING).length, 13, 'kid map must have 13 entries');
  assert.equal(KID_TO_BINDING['pragmaticdharma'], 'JWT_SECRET_PRAGMATICDHARMA');
  assert.equal(KID_TO_BINDING['sentinel'], 'JWT_SECRET_PRAGMATICDHARMA');
  assert.equal(KID_TO_BINDING['review'], 'JWT_SECRET_REVIEW');
  assert.equal(KID_TO_BINDING['boardreview'], 'JWT_SECRET_REVIEW');
});

test('CSP_CONNECT_SRC_HOSTS has exactly the 2 adminConnect projects (health + psychology)', () => {
  assert.deepStrictEqual(CSP_CONNECT_SRC_HOSTS, [
    'https://health.pragmaticdharma.org',
    'https://psychology.pragmaticdharma.org',
  ]);
});

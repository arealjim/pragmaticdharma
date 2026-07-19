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
  assert.equal(KNOWN_PROJECTS.length, 11, 'expected 11 project keys');
  assert.deepStrictEqual(KNOWN_PROJECTS, [
    'health', 'shield', 'ego-assessment', 'mindreader', 'psychtools',
    'astrology', 'practice', 'sentinel', 'bromnichord', 'discern', 'review',
  ]);
});

test('REDIRECT_ALLOWLIST has 13 hosts (11 projects + apex + retreats)', () => {
  assert.equal(REDIRECT_ALLOWLIST.size, 13, 'allowlist must have exactly 13 hosts');
  assert.ok(REDIRECT_ALLOWLIST.has('pragmaticdharma.org'));
  assert.ok(REDIRECT_ALLOWLIST.has('retreats.pragmaticdharma.org'));
  assert.ok(REDIRECT_ALLOWLIST.has('psychology.pragmaticdharma.org'));
});

test('HOST_TO_PROJECT has 11 entries and maps psychology.* to ego-assessment', () => {
  assert.equal(Object.keys(HOST_TO_PROJECT).length, 11, 'host map must have exactly 11 entries');
  assert.equal(HOST_TO_PROJECT['psychology.pragmaticdharma.org'], 'ego-assessment');
});

test('KID_TO_BINDING has 12 entries (11 projects + platform) and honors sentinel override', () => {
  assert.equal(Object.keys(KID_TO_BINDING).length, 12, 'kid map must have 12 entries');
  assert.equal(KID_TO_BINDING['pragmaticdharma'], 'JWT_SECRET_PRAGMATICDHARMA');
  assert.equal(KID_TO_BINDING['sentinel'], 'JWT_SECRET_PRAGMATICDHARMA');
  assert.equal(KID_TO_BINDING['review'], 'JWT_SECRET_REVIEW');
});

test('CSP_CONNECT_SRC_HOSTS has exactly the 2 adminConnect projects (health + psychology)', () => {
  assert.deepStrictEqual(CSP_CONNECT_SRC_HOSTS, [
    'https://health.pragmaticdharma.org',
    'https://psychology.pragmaticdharma.org',
  ]);
});

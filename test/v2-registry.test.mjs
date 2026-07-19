// Slice-0 freeze tests: each registry-derived structure must deep-equal the
// corresponding live literal in worker.js. These tests stay green through slice 1
// (when worker.js imports from the registry), at which point both sides share the
// same source and the test confirms the import wiring is correct. Removed in
// slice 1 along with the v2-slice-0 exports from worker.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Live literals from worker.js (v2-slice-0 freeze exports)
import {
  KNOWN_PROJECTS as workerKnownProjects,
  REDIRECT_ALLOWLIST as workerRedirectAllowlist,
  KID_TO_BINDING as workerKidToBinding,
  HOST_TO_PROJECT as workerHostToProject,
  CSP_CONNECT_SRC_HOSTS as workerCspConnectSrcHosts,
} from '../worker.js';

// Registry-derived equivalents
import {
  KNOWN_PROJECTS,
  REDIRECT_ALLOWLIST,
  KID_TO_BINDING,
  HOST_TO_PROJECT,
  CSP_CONNECT_SRC_HOSTS,
} from '../src/registry.js';

test('KNOWN_PROJECTS from registry matches worker literal', () => {
  assert.deepStrictEqual(KNOWN_PROJECTS, workerKnownProjects);
});

test('REDIRECT_ALLOWLIST from registry matches worker literal (13 hosts)', () => {
  assert.equal(REDIRECT_ALLOWLIST.size, 13, 'allowlist must have exactly 13 hosts');
  assert.deepStrictEqual(REDIRECT_ALLOWLIST, workerRedirectAllowlist);
});

test('HOST_TO_PROJECT from registry matches worker literal (11 entries)', () => {
  assert.equal(Object.keys(HOST_TO_PROJECT).length, 11, 'host map must have exactly 11 entries');
  assert.deepStrictEqual(HOST_TO_PROJECT, workerHostToProject);
});

test('KID_TO_BINDING from registry matches worker literal (12 entries: 11 projects + platform)', () => {
  assert.equal(Object.keys(KID_TO_BINDING).length, 12, 'kid map must have 12 entries');
  assert.deepStrictEqual(KID_TO_BINDING, workerKidToBinding);
});

test('CSP_CONNECT_SRC_HOSTS from registry matches worker literal (health + psychology)', () => {
  assert.equal(CSP_CONNECT_SRC_HOSTS.length, 2, 'exactly 2 adminConnect projects');
  assert.deepStrictEqual(CSP_CONNECT_SRC_HOSTS, workerCspConnectSrcHosts);
});

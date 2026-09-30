// v2 Slice 3: index-page cards are rendered from the registry instead of
// static per-project markup. This test freezes the exact HTML each live
// project's card must render — it was verified byte-identical to the
// original static markup at conversion time (see git history for
// pages/index.html before this slice), so a diff here means either the
// registry's card copy changed (update the fixture deliberately) or
// renderCards()'s markup drifted (bug).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { renderCards, adminProjectsJSON } from '../src/registry.js';

// 2026-09-29 (Jim): every registry project is hidden — the index shows only
// the static Psyche / Meditation Resources / Retreat Finder cards. Restoring a
// project's card = set its status back to 'live' and re-add its row here, e.g.
//   ['shield', 'Shield', '<cardDescription from projects.config.mjs>'],
const EXPECTED_CARDS = [];

function cardHtml(subdomain, title, desc) {
  return `  <a class="card-link" href="https://${subdomain}.pragmaticdharma.org">\n` +
    `    <div class="card">\n      <h3>${title}</h3>\n      <p>${desc}</p>\n      <span class="status live">Live</span>\n    </div>\n  </a>`;
}

test('renderCards() reproduces the frozen pre-Slice-3 card markup byte-for-byte', () => {
  const expected = EXPECTED_CARDS.map(([sd, t, d]) => cardHtml(sd, t, d)).join('\n\n');
  assert.equal(renderCards(), expected);
});

test('renderCards() emits exactly EXPECTED_CARDS.length cards, in index-page order', () => {
  const matches = [...renderCards().matchAll(/href="https:\/\/([a-z]+)\.pragmaticdharma\.org"/g)].map(m => m[1]);
  assert.deepStrictEqual(matches, EXPECTED_CARDS.map(([sd]) => sd));
});

test('adminProjectsJSON() has all 12 projects with key + label', () => {
  const projects = adminProjectsJSON();
  assert.equal(projects.length, 12);
  for (const p of projects) {
    assert.ok(p.key);
    assert.ok(p.label);
  }
  assert.deepStrictEqual(projects.find(p => p.key === 'boardreview'), { key: 'boardreview', label: 'Board Review' });
  assert.deepStrictEqual(projects.find(p => p.key === 'review'), { key: 'review', label: 'Review (staff)' });
});

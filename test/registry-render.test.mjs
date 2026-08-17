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

const EXPECTED_CARDS = [
  ['shield', 'Shield', 'Automated daily intelligence briefing. Collects news, Reddit discussions, market data, and conflict reports from 33+ sources, synthesized by AI into a security-focused morning brief.'],
  ['health', 'Health Tracker', 'Traditional Chinese Medicine body mapping and symptom tracking. Log daily observations and track patterns over time.'],
  ['mindreader', 'Mind Reader', 'Gaze-guided therapeutic tool. Tracks emotions, heart rate, and physiological signals via webcam while guiding your gaze across the screen.'],
  ['psychtools', 'PsychTools', 'Interactive DBT skills practice suite. 35 tools across mindfulness, interpersonal effectiveness, emotion regulation, and distress tolerance.'],
  ['discern', 'Discern', 'Calibration training game. Judge claims as true or false, state your confidence, and see how well your certainty tracks reality &mdash; trains spotting misinformation without sliding into blanket cynicism.'],
  ['practice', 'Practice Hub', 'Cycle-aware life management. Tasks and goals aligned with TCM organ clock, lunar phases, solar terms, and astrological transits. Natural language task entry with Five Element energy tagging.'],
  ['astrology', 'Transit Viewer', 'Personalized astrological transit timeline. Enter your birth data, see a Gantt-chart of upcoming planetary transits, and get AI-powered interpretations and interactive chat.'],
  ['sentinel', 'Sentinel', 'Preparedness scenarios, predictions, and daily assessment.'],
  ['bromnichord', 'Bromnichord', 'Browser omnichord with 8-bit chiptune voices. Pick chords on a circle-of-fifths wheel, set arpeggios, and strum a 10-segment light beam — all wrapped in psychedelic audio-reactive visuals.'],
];

function cardHtml(subdomain, title, desc) {
  return `  <a class="card-link" href="https://${subdomain}.pragmaticdharma.org">\n` +
    `    <div class="card">\n      <h3>${title}</h3>\n      <p>${desc}</p>\n      <span class="status live">Live</span>\n    </div>\n  </a>`;
}

test('renderCards() reproduces the frozen pre-Slice-3 card markup byte-for-byte', () => {
  const expected = EXPECTED_CARDS.map(([sd, t, d]) => cardHtml(sd, t, d)).join('\n\n');
  assert.equal(renderCards(), expected);
});

test('renderCards() emits exactly 9 cards, in index-page order', () => {
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

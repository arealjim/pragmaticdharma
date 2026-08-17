#!/usr/bin/env node
// `pd projects` — list every registered project (v2 Slice 4).
import { adminProjects } from '../src/registry.js';

const rows = adminProjects().map(p => ({
  key: p.key,
  host: `${p.subdomain}.pragmaticdharma.org`,
  gate: p.gate,
  status: p.status,
  customAuthTest: p.customAuthTest ? 'yes' : '',
}));

const columns = [
  ['key', 'KEY'],
  ['host', 'HOST'],
  ['gate', 'GATE'],
  ['status', 'STATUS'],
  ['customAuthTest', 'CUSTOM AUTH TEST'],
];

const widths = columns.map(([field, header]) =>
  Math.max(header.length, ...rows.map(r => String(r[field]).length))
);

function printRow(values) {
  console.log(values.map((v, i) => String(v).padEnd(widths[i])).join('  '));
}

printRow(columns.map(([, header]) => header));
printRow(widths.map(w => '-'.repeat(w)));
for (const row of rows) {
  printRow(columns.map(([field]) => row[field]));
}

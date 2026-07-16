// Minimal D1-compatible adapter over node:sqlite (in-memory), for unit tests.
// Implements the subset of the D1 API worker.js uses:
//   env.DB.prepare(sql).bind(...params).first() / .all() / .run()
// run() returns { meta: { changes } } like D1; first() returns the row or null;
// all() returns { results: [...] }.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SCHEMA_PATH = fileURLToPath(new URL('../schema.sql', import.meta.url));

export function createFakeD1() {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(SCHEMA_PATH, 'utf8'));

  return {
    // Raw handle for test seeding/inspection (not part of the D1 API).
    _sqlite: db,

    prepare(sql) {
      let params = [];
      const stmt = {
        bind(...args) {
          // D1 treats undefined bindings as errors; normalize null like prod would reject.
          params = args.map((a) => (a === undefined ? null : a));
          return stmt;
        },
        async first() {
          const row = db.prepare(sql).get(...params);
          return row === undefined ? null : row;
        },
        async all() {
          const rows = db.prepare(sql).all(...params);
          return { results: rows, success: true, meta: {} };
        },
        async run() {
          const info = db.prepare(sql).run(...params);
          return { success: true, meta: { changes: Number(info.changes) } };
        },
      };
      return stmt;
    },
  };
}

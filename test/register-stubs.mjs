// Module loader hooks so worker.js can be imported under plain Node for unit
// tests. wrangler bundles .html/.txt imports as text modules ([rules] in
// wrangler.toml); Node has no idea what to do with them, so stub every
// .html/.txt import as an empty-string default export. Page content is
// irrelevant to the auth logic under test.
//
// Usage: node --import ./test/register-stubs.mjs --test test/
import { registerHooks } from 'node:module';

registerHooks({
  load(url, context, nextLoad) {
    if (url.endsWith('.html') || url.endsWith('.txt')) {
      return {
        format: 'module',
        source: 'export default "";',
        shortCircuit: true,
      };
    }
    return nextLoad(url, context);
  },
});

#!/usr/bin/env node
// `pd add-project <key>` — semi-automatic project-onboarding flow (v2 Slice 4).
// Steps 1-3 (append registry entry, wrangler.toml codegen) are automatic;
// step 4 (Secrets Store secret creation) is semi-automatic — the beta
// secrets-store CLI has failed before (see CLAUDE.md "Sentinel temporary
// signing-key state"), so this always prints the dashboard fallback +
// generated value even when the CLI attempt looks like it might have worked,
// so nothing is lost if it silently didn't. Step 5 is a printed manual
// checklist (DNS, sub-worker snippet, grant, test); step 6 (deploy) is left
// to the operator. See docs/v2-registry-schema.md "pd add-project <key> flow"
// and docs/design-v2-registry.md.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const CONFIG_PATH = join(ROOT, 'projects.config.mjs');
const STORE_ID = '626a023faf5e4be98729d2f4b9849f09';

function usage(msg) {
  if (msg) console.error(`Error: ${msg}\n`);
  console.error('Usage: pd add-project <key> [--subdomain SUB] [--label "Human Name"]');
  console.error('                            [--gate worker-gate|api-gate] [--admin-connect]');
  console.error('                            [--test-probe PATH]');
  console.error("  <key> must be lowercase letters/digits/hyphens — becomes the D1 user_projects");
  console.error('  value, the JWT projects[] claim entry, and the open_beta:<key> config key.');
  process.exit(1);
}

function parseArgs(argv) {
  const [key, ...rest] = argv;
  if (!key || !/^[a-z][a-z0-9-]*$/.test(key)) usage(!key ? 'missing <key>' : `invalid key '${key}'`);
  const opts = { key, subdomain: key, label: key, gate: 'worker-gate', adminConnect: false, testProbe: '/' };
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === '--subdomain') opts.subdomain = rest[++i];
    else if (arg === '--label') opts.label = rest[++i];
    else if (arg === '--gate') opts.gate = rest[++i];
    else if (arg === '--admin-connect') opts.adminConnect = true;
    else if (arg === '--test-probe') opts.testProbe = rest[++i];
    else usage(`unknown flag '${arg}'`);
  }
  if (opts.gate !== 'worker-gate' && opts.gate !== 'api-gate') {
    usage(`--gate must be 'worker-gate' or 'api-gate', got '${opts.gate}'`);
  }
  return opts;
}

function jsString(s) {
  return `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

async function main() {
  const { key, subdomain, label, gate, adminConnect, testProbe } = parseArgs(process.argv.slice(2));

  const { PROJECTS } = await import(CONFIG_PATH);
  if (PROJECTS.some(p => p.key === key)) usage(`project '${key}' already exists in projects.config.mjs`);
  if (PROJECTS.some(p => p.subdomain === subdomain)) usage(`subdomain '${subdomain}' is already claimed`);
  if (PROJECTS.some(p => p.kid === key)) usage(`kid '${key}' is already claimed`);

  // --- steps 1-2: append the entry (status: 'soon' — not advertised until an
  // operator flips it to 'live' once the sub-worker is actually deployed) ---
  const entry = [
    `  // ── ${key} ──`,
    `  // Added by \`pd add-project\` — fill in a real description, then flip`,
    `  // status to 'live' once the sub-worker is deployed and reachable.`,
    `  {`,
    `    key:          ${jsString(key)},`,
    `    subdomain:    ${jsString(subdomain)},`,
    `    kid:          ${jsString(key)},`,
    `    gate:         ${jsString(gate)},`,
    `    status:       'soon',`,
    `    adminConnect: ${adminConnect},`,
    `    label:        ${jsString(label)},`,
    `    adminLabel:   ${jsString(label)},`,
    `    cardTitle:       ${jsString(label)},`,
    `    cardDescription: 'TODO: write index-card marketing copy for ${key}.',`,
    `    testProbe:    ${jsString(testProbe)},`,
    `  },`,
  ].join('\n');

  const configText = readFileSync(CONFIG_PATH, 'utf8');
  const closeIdx = configText.lastIndexOf('\n];');
  if (closeIdx === -1) throw new Error('could not find the end of the PROJECTS array in projects.config.mjs');
  const nextConfigText = `${configText.slice(0, closeIdx)}\n\n${entry}${configText.slice(closeIdx)}`;
  writeFileSync(CONFIG_PATH, nextConfigText);
  console.log(`[1/6] Appended '${key}' to projects.config.mjs (status: 'soon')`);

  // --- step 3: wrangler.toml codegen ---
  execFileSync('node', [join(ROOT, 'scripts', 'gen-wrangler.mjs')], { stdio: 'inherit' });
  console.log(`[2/6] Regenerated wrangler.toml's secrets block`);

  // --- step 4: Secrets Store secret (best-effort; dashboard is the expected
  // fallback — the beta CLI has failed before) ---
  const bindingName = `JWT_SECRET_${key.toUpperCase().replace(/-/g, '_')}`;
  const secretValue = crypto.randomBytes(32).toString('hex');
  let cliSucceeded = false;
  try {
    execFileSync('wrangler', ['secrets-store', 'secret', 'create', STORE_ID, '--name', bindingName, '--scopes', 'workers', '--remote'], {
      input: secretValue,
      stdio: ['pipe', 'inherit', 'inherit'],
    });
    cliSucceeded = true;
  } catch {
    // expected — see comment above
  }
  console.log(`[3/6] Secrets Store entry '${bindingName}': ${cliSucceeded ? 'CLI create attempted (verify with the list command below)' : 'CLI attempt failed or unavailable — use the dashboard fallback below'}`);

  // --- steps 5-6: printed manual checklist ---
  console.log('');
  console.log('=== Manual checklist ===');
  console.log('');
  console.log(`1. Verify/create the Secrets Store secret (dashboard fallback if the CLI attempt above failed):`);
  console.log(`     Cloudflare dashboard → Workers & Pages → Secrets Store → ${STORE_ID} → Add secret`);
  console.log(`     Name: ${bindingName}   Value (save to KeePassXC — printed once):`);
  console.log(`       ${secretValue}`);
  console.log(`     Or retry the CLI:`);
  console.log(`       printf '%s' '<value>' | wrangler secrets-store secret create ${STORE_ID} --name ${bindingName} --scopes workers --remote`);
  console.log('');
  console.log(`2. DNS + route for ${subdomain}.pragmaticdharma.org (Cloudflare dashboard), and deploy the sub-worker with:`);
  console.log(`     - wrangler.toml: [[secrets_store_secrets]] binding = "JWT_SECRET", store_id = "${STORE_ID}", secret_name = "${bindingName}"`);
  console.log(`     - kid header '${key}' on the JWT it verifies (see shared/auth-cloudflare.js or shared/auth-flask.py)`);
  console.log(`     - hasProjectAccess(payload, '${key}')`);
  console.log(`     - unauthenticated/denied → refresh bounce to https://pragmaticdharma.org/login?redirect=<this-page>`);
  console.log('');
  console.log(`3. Grant yourself access: ./pd approve <your-email>  (or toggle the '${label}' badge in /admin if already approved)`);
  console.log('');
  console.log(`4. node test-auth.js --only ${key}   (once the sub-worker is live and JWT_SECRET_${key.toUpperCase().replace(/-/g, '_')} is set in your env)`);
  console.log('');
  console.log(`5. npm run deploy   (platform hub — picks up the new registry entry + wrangler.toml block)`);
  console.log('');
  console.log(`6. Flip status: 'soon' -> 'live' in projects.config.mjs (and write real cardTitle/cardDescription copy) once the card should show on the index page, then deploy again.`);
}

main().catch(err => {
  console.error(`add-project failed: ${err.message}`);
  process.exit(1);
});

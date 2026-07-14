#!/usr/bin/env node
// validate.mjs: assert the catalog is well-formed and access-correct.
// Dependency-free (Node stdlib only). Exits non-zero on the first failing rule set.
//
// Kaveh's rule: if it is Cypher, it needs an API key. Always. The whisper.security
// graph is a KEYED surface: every catalog entry runs Cypher, so every entry is keyed
// (the key is unlimited). Keyless is only a rate-limited playground (100/window), a
// taste for new users/agents, never production. The genuine keyless half of Whisper is
// the non-Cypher identity ops (verify/rdap), which are not in this catalog.
//
// Rules enforced:
//   1. Every entry has id / title / purpose / prompt and provenance === true.
//   2. Every entry's access is "keyed" (it is Cypher).
//   3. Every entry declares a boolean `playgroundTryable`, and it is coherent:
//      only single-request direct READ verbs may be playground-tryable (a multi-step
//      flow or the write verb would burn the keyless cap, so it is never tryable).
//   4. The whisper.agents control plane is NEVER exposed as a catalog entry.
//   5. No forbidden tokens (secrets / internal infra / AI attribution) anywhere.
//   6. ids are unique.
//   7. Every entry carries a root-relative docPath (/docs/...), and the graph block
//      carries docsBase + the flowRun contract, so every channel can build docs links
//      (docsBase + docPath) and run flows without extra configuration.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const catalog = JSON.parse(readFileSync(join(root, 'catalog.json'), 'utf8'));
const errors = [];

const WRITE_VERBS = ['whisper.submit'];
const CONTROL_VERBS = ['whisper.agents'];

// Public-repo hygiene: GENERIC leak patterns only. We deliberately do NOT
// enumerate the specific internal hostnames, backend module names, or vendor
// terms here, because spelling them out in a public file discloses the very
// things this check exists to keep out. The specific-token scan runs in the
// private pre-publish pipeline; this public gate catches the generic shapes.
const FORBIDDEN = [
  /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,      // any private key
  /\b[a-z][a-z0-9]{2,}_live_[A-Za-z0-9_-]{16,}/i,               // a minted live key
  /\b[a-z]{2,4}_[a-f0-9]{24,}\b/i,                              // a generic minted token
  /\buserId\b/, /\buser_[0-9a-z]{6,}/i,                         // tenant identifiers
  /100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d+\.\d+/,      // RFC 6598 shared range
  /:8080\b/, /\/actuator\b/i,                                  // ops surfaces
  /co-authored-by:/i,                                          // any authorship trailer
];

if (catalog.schemaVersion !== 1) errors.push(`schemaVersion must be 1, got ${catalog.schemaVersion}`);
if (!Array.isArray(catalog.entries) || catalog.entries.length === 0) errors.push('entries[] missing/empty');

// Rule 7 (graph block): docsBase + the flowRun contract are part of the catalog's contract.
const DOC_PATH_RE = /^\/docs(\/[a-z0-9-]+)+$/;
if (typeof catalog.graph?.docsBase !== 'string' || !/^https:\/\/[a-z0-9.-]+$/.test(catalog.graph.docsBase))
  errors.push(`graph.docsBase must be an https origin with no trailing slash (got ${JSON.stringify(catalog.graph?.docsBase)})`);
const fr = catalog.graph?.flowRun;
if (!fr || typeof fr.endpoint !== 'string' || !fr.endpoint.startsWith('https://')
    || fr.method !== 'POST' || fr.auth !== 'X-API-Key' || typeof fr.bodyShape?.slug !== 'string')
  errors.push('graph.flowRun must carry {endpoint(https), method:POST, auth:X-API-Key, bodyShape.slug}');

const seen = new Set();
for (const e of catalog.entries ?? []) {
  const at = `entry ${e.id ?? '<no-id>'}`;
  if (!e.id) errors.push(`${at}: missing id`);
  if (!e.title) errors.push(`${at}: missing title`);
  if (!e.purpose) errors.push(`${at}: missing purpose`);
  if (!e.prompt) errors.push(`${at}: missing prompt`);
  if (e.provenance !== true) errors.push(`${at}: provenance must be true`);
  if (typeof e.docPath !== 'string' || !DOC_PATH_RE.test(e.docPath))
    errors.push(`${at}: docPath must be a root-relative /docs/... path (got ${JSON.stringify(e.docPath)})`);
  if (e.id) {
    if (seen.has(e.id)) errors.push(`${at}: duplicate id`);
    seen.add(e.id);
  }

  const execBlob = JSON.stringify(e.exec ?? {});
  const mode = e.exec?.mode;
  if (!['direct', 'flow'].includes(mode)) errors.push(`${at}: exec.mode must be direct|flow (got ${mode})`);

  // Rule 4: never expose the control plane as an entry.
  if (CONTROL_VERBS.some(v => execBlob.includes(v)))
    errors.push(`${at}: exposes forbidden control-plane verb (whisper.agents)`);

  // Rule 2: it is Cypher, so it is keyed. Every entry, always.
  if (e.access !== 'keyed') errors.push(`${at}: access must be "keyed" (it is Cypher) but got ${e.access}`);

  // Rule 3: playgroundTryable is a boolean, and coherent with Kaveh's rule.
  if (typeof e.playgroundTryable !== 'boolean') {
    errors.push(`${at}: playgroundTryable must be a boolean (got ${typeof e.playgroundTryable})`);
  } else if (e.playgroundTryable) {
    // Only single-request direct READ verbs can be sampled in the 100/window playground.
    const isWrite = WRITE_VERBS.some(v => execBlob.includes(v));
    if (mode !== 'direct')
      errors.push(`${at}: playgroundTryable=true but exec.mode is "${mode}": a multi-step flow would burn the keyless cap`);
    if (isWrite)
      errors.push(`${at}: playgroundTryable=true but it is a write verb: writes are keyed, never playground-tryable`);
  }
}

// Rule 5: forbidden-token scan over the whole serialized catalog.
const serialized = JSON.stringify(catalog);
for (const re of FORBIDDEN) {
  const m = serialized.match(re);
  if (m) errors.push(`forbidden token present: ${re} (matched "${m[0]}")`);
}

if (errors.length) {
  console.error(`validate: FAIL (${errors.length})`);
  for (const e of errors) console.error('  - ' + e);
  process.exit(1);
}

const keyed = catalog.entries.filter(e => e.access === 'keyed').length;
const tryable = catalog.entries.filter(e => e.playgroundTryable).length;
console.log(`validate: PASS. ${catalog.entries.length} entries, all keyed (${keyed}); playground-tryable direct reads=${tryable}`);

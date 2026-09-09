// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Runs dist/demo.html's own scripts under Node against a minimal DOM stub.
//
// This is not a substitute for opening the page — it cannot see layout, CSS or
// event wiring. What it does check is the part that would be silently wrong:
// that the inlined WebAssembly initialises from base64, that every scenario
// reaches the verdict it is supposed to demonstrate, and that the wording next
// to a failure names the real cause. A demo whose "tampered" case quietly
// renders green is worse than no demo.
//
//   node demo/verify.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '..', 'dist', 'demo.html'), 'utf8');

const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
if (scripts.length !== 2) throw new Error(`expected 2 script blocks, found ${scripts.length}`);

// Minimal stand-ins for the handful of DOM features the page uses. Anything it
// touches that is not modelled here throws, which is the point: a silent stub
// would let the page drift away from what a browser actually provides.
const nodes = new Map();
const el = (id) => {
  if (!nodes.has(id)) {
    nodes.set(id, {
      id, innerHTML: '', textContent: '', className: '', style: {},
      value: '', files: [],
      classList: {
        _s: new Set(),
        add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
        contains(c) { return this._s.has(c); },
      },
      addEventListener() {},
      getAttribute() { return null; },
      setAttribute() {},
    });
  }
  return nodes.get(id);
};

const PAGE_URL = 'file:///C:/demo/dist/demo.html';

const sandbox = {
  document: {
    getElementById: el,
    createElement: () => el('scratch'),
    // The shim resolves a URL against `document.currentScript.src`. For an
    // inline script a browser sets this to the empty string, which resolves to
    // the page itself; it is then unused, because the wasm arrives as bytes.
    // Modelled rather than stubbed away so the stub cannot be more forgiving
    // than a browser.
    currentScript: { src: '' },
  },
  location: { href: PAGE_URL },
  window: {}, console, TextDecoder, TextEncoder, URL, Date, Math, JSON,
  atob: (s) => Buffer.from(s, 'base64').toString('binary'),
  btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
  WebAssembly, Uint8Array, Object, Error, fetch: undefined,
  performance, crypto: globalThis.crypto,
  setTimeout, clearTimeout, queueMicrotask,
};
sandbox.self = sandbox;
sandbox.globalThis = sandbox;

const ctx = vm.createContext(sandbox);
vm.runInContext(scripts[0], ctx, { filename: 'wasm-bindgen-shim.js' });
vm.runInContext(scripts[1], ctx, { filename: 'demo.js' });

// The page's main() is async; give the wasm init a turn to settle.
await new Promise((r) => setTimeout(r, 300));

let failures = 0;
const check = (label, actual, expected) => {
  const ok = actual === expected;
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) console.log(`      expected ${JSON.stringify(expected)}\n      actual   ${JSON.stringify(actual)}`);
};
const contains = (label, hay, needle) => {
  const ok = String(hay).includes(needle);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) console.log(`      ${JSON.stringify(String(hay).slice(0, 200))}\n      lacks ${JSON.stringify(needle)}`);
};

console.log(`\n--- wasm initialised from the inlined bundle ---`);
const version = vm.runInContext('wasm_bindgen.version()', ctx);
check('core version is reported', typeof version === 'string' && version.length > 0, true);
console.log(`      core v${version}`);

const scenarios = vm.runInContext('SCENARIOS', ctx);
const load = (i) => {
  vm.runInContext(`loadScenario(SCENARIOS[${i}])`, ctx);
  return {
    headline: el('banner-headline').textContent,
    because: el('banner-because').textContent,
    banner: el('banner').className,
    error: el('error').style.display === 'block' ? el('error-text').textContent : null,
    evidence: el('evidence').innerHTML,
    assertions: el('assertions').innerHTML,
    shown: el('verdict').classList.contains('on'),
  };
};

// Each scenario exists to demonstrate one distinction. If it lands on the
// wrong verdict the demo teaches the wrong thing, so the expected headline is
// pinned rather than merely observed.
const EXPECTED = [
  ['Verified',                                'v-pass'],
  ['Policy not satisfied',                    'v-warn'],
  ['Failed',                                  'v-fail'],
  ['Failed',                                  'v-fail'],
  ['Unavailable',                             'v-none'],
  ['Verified \u2014 and about this artifact', 'v-pass'],
  ['Wrong artifact',                          'v-fail'],
  ['Unavailable',                             'v-none'],
];

for (let i = 0; i < EXPECTED.length; i++) {
  console.log(`\n--- scenario ${i + 1}: ${scenarios[i].label} ---`);
  const r = load(i);
  check('rendered without throwing', r.error, null);
  check('results are visible', r.shown, true);
  check('headline', r.headline, EXPECTED[i][0]);
  check('banner styling', r.banner, `banner ${EXPECTED[i][1]}`);
}

// The payload is what the statement says; the rest of the page is about whether
// to believe it. The three cases must stay visually distinct, because calling a
// digest "the payload" would misrepresent what was signed.
console.log('\n--- payload: a carried document ---');
load(0);
contains('content type is shown', el('payload-meta').innerHTML, 'Content type');
contains('sha-256 is qualified against the claim digest',
  el('payload-meta').innerHTML, 'Not the claim digest');
check('content is offered', el('payload-details').style.display, '');
check('body is non-empty', el('payload-body').textContent.length > 0, true);

console.log('\n--- payload: a hash envelope is a digest, not content ---');
const env = load(7);
check('rendered without throwing', env.error, null);
contains('labelled as a digest', el('payload-meta').innerHTML, 'Digest, not content');
contains('says the statement does not carry the content',
  el('payload-note').textContent, 'not the artifact itself');
// The whole point: no sha256-of-a-digest anywhere near this.
check('no misleading sha-256 row', el('payload-meta').innerHTML.includes('SHA-256 of the payload'), false);
check('no content pane to mistake for the document', el('payload-details').style.display, 'none');

// The two cases that are easiest to render as the same red box, and must not be.
// The two tampering cases are easiest to render as the same red box, and must
// not be. Note that payload-tampered fails its statement signature *as well as*
// its binding — altering the payload breaks the signature over it — so the
// headline names the signature, which is the finding that indicts the bytes.
// The binding result stays visible in the evidence table rather than being
// hidden behind the higher-precedence failure.
console.log('\n--- a tampered payload is not a tampered receipt ---');
const tamperedPayload = load(2);
contains('names the signature as the primary finding', tamperedPayload.because, 'signature did not verify');
contains('binding row still shows the receipt points elsewhere',
  tamperedPayload.evidence, 'Not this statement');
const tamperedReceipt = load(3);
contains("says the statement's own signature is intact", tamperedReceipt.because, "root signature");
contains('statement signature still reported valid', tamperedReceipt.evidence, 'Valid');

console.log('\n--- an unknown key is unproven, not disproven ---');
const stale = load(4);
contains('rotation and forgery look alike', stale.because, 'rotation');
check('not styled as a failure', stale.banner.includes('v-fail'), false);

console.log('\n--- policy failure names what it saw ---');
const wrongPolicy = load(1);
contains('a failing assertion is rendered', wrongPolicy.assertions, 't-fail');
contains('detail names the observed issuer', wrongPolicy.assertions, 'musa-mst-july');
contains('and the verdict separates policy from tampering', wrongPolicy.because, 'different finding');

console.log('\n--- editing the policy changes the verdict, with no rebuild ---');
load(0);
check('starts verified', el('banner-headline').textContent, 'Verified');
el('policy').value = JSON.stringify({
  policyId: 'demo/edited', policyVersion: '1',
  assertions: { issuer: ['not-this-ledger.example'] },
});
vm.runInContext('run()', ctx);
check('flips on re-evaluate', el('banner-headline').textContent, 'Policy not satisfied');
contains('and reports the edited policy', el('policy-meta').textContent, 'demo/edited');

console.log('\n--- a malformed policy is surfaced, not swallowed ---');
el('policy').value = '{ not json';
vm.runInContext('run()', ctx);
check('error is shown', el('error').style.display, 'block');
check('results are hidden', el('verdict').classList.contains('on'), false);

// Binding answers a different question from everything else on the page, and
// the three outcomes must stay distinguishable. Collapsing "I could not check"
// into "this is the wrong file" would halt a release over a mode the operator
// typed wrong.
console.log('\n--- artifact binding: the check a signature cannot make ---');
const bound = load(5);
contains('the evidence table names binding', bound.evidence, 'Artifact binding');
contains('reported as bound', bound.evidence, 'Bound');
contains('names the file it compared', bound.evidence, 'artifact.bin');
contains('records the mode as declared', bound.evidence, 'declared mode payload-bytes');
check('the gap is no longer claimed', el('gap-artifact').style.display, 'none');

const wrong = load(6);
contains('a genuine statement about another file is a failure', wrong.because, 'genuine');
contains('the statement signature is still reported valid', wrong.evidence, 'Valid');
contains('the mismatch names both digests', wrong.evidence, 'does not equal');
check('the gap is restated rather than hidden', el('gap-artifact').style.display, '');

// Without an artifact the page must say so rather than implying a file was
// checked. This is the state every user-loaded statement starts in.
const noArtifact = load(0);
contains('no artifact means not requested', noArtifact.evidence, 'Not requested');

// A mode that does not fit the statement is a limitation of the request. The
// page must refuse to compare rather than manufacture a mismatch.
//
// This fixture carries no receipt, so the banner stops at the receipt gap
// before binding is ever consulted — receipt precedence outranks binding, and
// that ordering is worth pinning too. The binding result is still reported in
// the evidence table, which is where this section reads it.
console.log('\n--- a mode that does not fit refuses rather than accuses ---');
load(7);
check('the banner stops at the missing receipt', el('banner-headline').textContent, 'Unavailable');
contains('the envelope binds under payload-digest', el('evidence').innerHTML, 'Bound');
contains('recording the declared mode', el('evidence').innerHTML, 'declared mode payload-digest');
contains('and saying what matched', el('evidence').innerHTML, 'equals the statement');

el('binding-mode').value = 'payload-bytes';
vm.runInContext('run()', ctx);
contains('switching to the wrong mode cannot compare', el('evidence').innerHTML, 'Cannot compare');
check('and never reports a mismatch it has no evidence for',
  el('evidence').innerHTML.includes('Mismatch'), false);
contains('naming the hash envelope as the reason', el('evidence').innerHTML, 'Hash Envelope');
check('never styled as a failure', el('banner').className.includes('v-fail'), false);

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);

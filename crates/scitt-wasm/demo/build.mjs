// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Produces dist/demo.html: one file, no server, no network, no build tooling
// on the consuming side.
//
// Everything is inlined — the WebAssembly, the wasm-bindgen shim, and the
// scenario bytes. That is not a packaging convenience. The page claims that
// nothing leaves the browser, and a page that fetches its own engine at load
// time is not in a position to make that claim. It also means the artifact can
// be hosted by anything that can serve a file, or opened from disk with no
// host at all, which is what makes it usable at a demo.
//
//   node demo/build.mjs
//
// Run wasm-pack first:
//   wasm-pack build --target no-modules --out-dir pkg-nomodules --release

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const crate = join(here, '..');
const repo = join(crate, '..', '..');
const pkg = join(crate, 'pkg-nomodules');
const fixtures = join(repo, 'corpus', 'fixtures');
const policies = join(repo, 'corpus', 'policies');

const b64 = (path) => readFileSync(path).toString('base64');
const b64json = (value) => Buffer.from(JSON.stringify(value, null, 2)).toString('base64');

// Built from the corpus policy for the same statement, so the issuer pins stay
// in step with the fixture when the corpus is regenerated; only the payload
// rules are the demo's own.
const payloadPolicy = (sourceRepository) => {
  const base = JSON.parse(readFileSync(join(policies, 'image-reproduction.json'), 'utf8'));
  return b64json({
    policyId: 'demo/payload-claims',
    policyVersion: '1',
    assertions: {
      ...base.assertions,
      payloadJson: [
        { path: ['component', 'app'], text: { equals: 'mst' } },
        { path: ['component', 'provenance', 'source-repository'], text: { equals: sourceRepository } },
        { path: ['component', 'provenance', 'reproduction-record-sha256'], exists: true },
      ],
    },
  });
};

// The corpus root, lifted out of the statement that carries it. A real
// deployment takes its roots from its own trust store, never from the
// statement; the scenario does this only because the corpus has no separate
// root file, and it labels it accordingly.
const corpusRootPem = (() => {
  const bytes = readFileSync(join(fixtures, 'transparent-statement.cose'));
  for (let i = 0; i + 4 < bytes.length; i++) {
    if (bytes[i] !== 0x30 || bytes[i + 1] !== 0x82) continue;
    const der = bytes.subarray(i, i + 4 + ((bytes[i + 2] << 8) | bytes[i + 3]));
    let cert;
    try { cert = new X509Certificate(der); } catch { continue; }
    if (cert.subject === 'CN=Example Corpus Root CA' && cert.issuer === cert.subject) {
      return cert.toString();
    }
  }
  throw new Error('the corpus root was not found in transparent-statement.cose');
})();
const serviceCertPem = readFileSync(join(fixtures, 'mst-test-service-cert.pem'), 'utf8');

// Real artifacts from the conformance corpus, not fabricated ones. A demo
// built on synthetic bytes demonstrates the demo.
//
// Deliberately excluded: any statement carrying partner or customer evidence.
// This artifact is meant to be handed around, and such payloads should not
// travel inside it. Load one through the file picker instead — the page treats
// a dropped file exactly the same way.
const SCENARIOS = [
  {
    label: 'Verified',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    note: 'A real MST transparent statement, its ledger key set, and a policy it satisfies.',
  },
  {
    label: 'Policy not satisfied',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'wrong-issuer.json')),
    note: 'The same statement, unaltered. Only the rules changed \u2014 this policy '
        + 'accepts a transparency service the statement was not registered with.',
  },
  {
    label: 'Payload altered after signing',
    statement: b64(join(fixtures, 'payload-tampered.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    note: 'Two findings at once, and the page reports the one that indicts the bytes. The '
        + 'signature no longer covers this payload, so it fails first. The receipt is '
        + 'genuine and its inclusion proof still verifies \u2014 look at "Receipt commits to '
        + 'these bytes" to see it pointing at a different claim digest.',
  },
  {
    label: 'Receipt signature fails',
    statement: b64(join(fixtures, 'tampered-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    note: 'The receipt was altered. The statement\u2019s own signature is untouched, and '
        + 'the page says so rather than condemning the whole file.',
  },
  {
    label: 'Key set does not hold the key',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'other-service-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    note: 'A rotation and a forgery look identical from here, so this is reported as '
        + 'unproven rather than as a failure.',
  },
  {
    label: 'Bound to its artifact',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    artifact: b64(join(fixtures, 'artifact.bin')),
    artifactName: 'artifact.bin',
    bindingMode: 'payload-bytes',
    note: 'The same verified statement, now compared against the file it describes. This is '
        + 'the only scenario here that says anything about a file on disk \u2014 everything '
        + 'else says the statement is genuine, which is a weaker claim than it looks.',
  },
  {
    label: 'Wrong artifact',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    artifact: b64(join(fixtures, 'bad-artifact.bin')),
    artifactName: 'bad-artifact.bin',
    bindingMode: 'payload-bytes',
    note: 'The failure a signature check cannot catch. Signature, receipt, inclusion proof '
        + 'and policy all pass \u2014 the statement is entirely genuine, and it is about a '
        + 'different file. Without an artifact this run would have shown a green tick.',
  },
  {
    label: 'Hash envelope',
    statement: b64(join(fixtures, 'hash-envelope.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: '',
    artifact: b64(join(fixtures, 'hash-envelope-artifact.spdx.json')),
    artifactName: 'hash-envelope-artifact.spdx.json',
    bindingMode: 'payload-digest',
    note: 'The signed payload is a digest of the artifact rather than the artifact itself '
        + '(RFC 9995). This fixture carries no receipt, so the verdict stops at that gap '
        + 'before binding is reached \u2014 read the binding in the evidence table, where it '
        + 'is bound to the file below. Switch the mode to payload-bytes to watch it refuse '
        + 'to compare rather than report a mismatch it has no evidence for.',
  },
  {
    label: 'Claims inside the payload',
    statement: b64(join(fixtures, 'image-reproduction', 'statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: payloadPolicy('https://github.com/microsoft/scitt-ccf-ledger'),
    note: 'The policy asserts on fields inside the signed JSON payload: which component this '
        + 'is, the repository it was built from, and that it commits to a reproduction record. '
        + 'The payload is read only because the issuer signed a content type saying it is JSON.',
  },
  {
    label: 'Payload claim not satisfied',
    statement: b64(join(fixtures, 'image-reproduction', 'statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: payloadPolicy('https://github.com/example/another-repository'),
    note: 'The same genuine statement. The policy now requires a different source repository, '
        + 'so one payload assertion fails while signature, receipt and the other claims pass.',
  },
  {
    label: 'Anchored to a trusted root',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    roots: corpusRootPem,
    rootsName: 'example-corpus-root.pem',
    note: 'The signer\u2019s chain now has to lead to a root you trust, so "Signer certificate '
        + 'chain" reads Anchored and the chain gap leaves the Not checked list. For the demo '
        + 'the root is the corpus test root; in practice it comes from your own trust store, '
        + 'never from the statement.',
  },
  {
    label: 'Chain does not reach the trusted root',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    roots: serviceCertPem,
    rootsName: 'unrelated-root.pem',
    note: 'The same genuine statement, with a trusted root its chain does not lead to. The '
        + 'signature still verifies \u2014 it is the signer\u2019s identity that is not '
        + 'established, and that is a failure, not a gap.',
  },
  {
    label: 'Key set vouched for by the service',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'mst-test-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    serviceCert: serviceCertPem,
    serviceCertName: 'mst-test-service-cert.pem',
    note: 'The ledger\u2019s service certificate names the one key receipts may be checked '
        + 'with. A key set served through a proxy or cache can no longer add keys of its own.',
  },
  {
    label: 'Key set not vouched for',
    statement: b64(join(fixtures, 'transparent-statement.cose')),
    keys: b64(join(fixtures, 'other-service-scitt-keys.cbor')),
    policy: b64(join(policies, 'fixture-mst.json')),
    serviceCert: serviceCertPem,
    serviceCertName: 'mst-test-service-cert.pem',
    note: 'Another service\u2019s keys, checked against this service\u2019s certificate. '
        + 'No key in the set is the one the certificate vouches for, so nothing is verified '
        + 'with it.',
  },
];

const shim = readFileSync(join(pkg, 'scitt_wasm.js'), 'utf8');
const wasm = b64(join(pkg, 'scitt_wasm_bg.wasm'));

let html = readFileSync(join(here, 'index.html'), 'utf8');

// `</script>` anywhere in an inlined string would close the surrounding tag and
// hand the rest of the file to the HTML parser. Nothing here should contain it,
// but "should" is doing too much work when the failure mode is a blank page.
const guard = (s, what) => {
  if (/<\/script/i.test(s)) throw new Error(`${what} contains a closing script tag`);
  return s;
};

const scenariosJson = guard(JSON.stringify(SCENARIOS), 'scenario data');

// Ordered so that no replacement can be re-scanned by a later one: the shim is
// last because it is the only value large enough to plausibly contain another
// placeholder's text.
html = html
  .replace('__SCENARIOS_JSON__', () => scenariosJson)
  .replace('__WASM_B64__', () => wasm)
  .replace('__WASM_BINDGEN_JS__', () => guard(shim, 'the wasm-bindgen shim'));

for (const left of ['__SCENARIOS_JSON__', '__WASM_B64__', '__WASM_BINDGEN_JS__']) {
  if (html.includes(left)) throw new Error(`placeholder ${left} was not replaced`);
}

const outDir = join(crate, 'dist');
mkdirSync(outDir, { recursive: true });
const out = join(outDir, 'demo.html');
writeFileSync(out, html);

console.log(`${out}  ${(Buffer.byteLength(html) / 1024 / 1024).toFixed(2)} MB`);
console.log(`  wasm      ${(readFileSync(join(pkg, 'scitt_wasm_bg.wasm')).length / 1024).toFixed(0)} KB`);
console.log(`  scenarios ${SCENARIOS.length}`);

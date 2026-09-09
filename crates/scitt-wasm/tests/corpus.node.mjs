// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Cross-implementation check against corpus/README.md, run through the same
// JavaScript boundary Ledger Explorer will use.
//
// The pinned values below are not test data. They are the identity of a real
// transparent statement, independently confirmed against the .NET prototype and
// pyscitt. If one of them changes, the definition of "the same statement" has
// changed, and every receipt ever issued against the old definition is
// affected. A failure here is not a test to update.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  verifyStatement,
  inspectStatement,
  claimDigest,
  evaluatePolicy,
  statementPayload,
  bindArtifact,
} from '../pkg-node/scitt_wasm.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, '..', '..', '..', 'corpus', 'fixtures');
const read = (name) => new Uint8Array(readFileSync(join(fixtures, name)));

const PINNED = {
  signedStatementLength: 8462,
  claimDigest: '5207494c12c986e33324c602e535717f67f0a6b56235f413e4a07d4d66d59565',
  merkleRoot: 'f369f5f4ce1e2bf6aa120e7f86e907130ede4ed75944e663d4c7b0a14da35993',
  statementAlg: -37, // PS256
  // ES384, not the ES256 that corpus/README.md claimed until the WASM shim
  // reproduced these values and disagreed. The header alg selects the curve
  // the root signature is verified against, so this one is load-bearing.
  receiptAlg: -35,
};

const ISSUER = 'musa-mst-july.confidential-ledger.azure.com';

let failures = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) {
    console.log(`      expected ${JSON.stringify(expected)}`);
    console.log(`      actual   ${JSON.stringify(actual)}`);
  }
};

const genuine = read('transparent-statement.cose');
const keys = read('musa-mst-july-scitt-keys.cbor');
const staleKeys = read('stale-scitt-keys.cbor');

// ---------------------------------------------------------------------------
// 1. The genuine statement reproduces every pinned value.
// ---------------------------------------------------------------------------
console.log('\n--- genuine transparent statement ---');
const verified = JSON.parse(verifyStatement(genuine, keys));
const receipt = verified.receipts[0];

check('signed statement length', verified.signedStatementLength, PINNED.signedStatementLength);
check('claim digest', verified.claimDigest, PINNED.claimDigest);
check('merkle root', receipt.root, PINNED.merkleRoot);
check('statement algorithm', verified.algorithm.value, PINNED.statementAlg);
check('statement algorithm name', verified.algorithm.name, 'PS256');
check('receipt algorithm', receipt.algorithm.value, PINNED.receiptAlg);
check('receipt algorithm name', receipt.algorithm.name, 'ES384');
check('statement signature verified', verified.signatureValid, true);
check('root signature verified', receipt.rootSignatureValid, true);
check('receipt bound to statement', receipt.boundToStatement, true);
check('key resolved', receipt.keyLookup, 'found');
check('receipt fully verified', receipt.fullyVerified, true);
check('four-certificate chain', verified.certificateChainLength, 4);
check('any receipt verified', verified.anyReceiptVerified, true);
check('standalone claim digest agrees', claimDigest(genuine), PINNED.claimDigest);

const inspected = JSON.parse(inspectStatement(genuine));
check('inspect claim digest agrees', inspected.claimDigest, PINNED.claimDigest);
check('inspect sees one receipt', inspected.receiptsPresent, 1);

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 2. The issuer is reported, never enforced.
//
//    The key set carries no issuer. A receipt from another transparency
//    service is signed by that service's key and fails verification on its own
//    merits, so scoping the key set added nothing a signature check did not
//    already do. What a caller actually needs is the issuer as a *fact* it can
//    hold its own policy against — so it has to be in the output.
// ---------------------------------------------------------------------------
console.log('\n--- issuer is reported, not enforced ---');
check('receipt names its issuer', receipt.issuer, ISSUER);
check('key set is not issuer-scoped', verified.keySet.scoped, undefined);
check('key set reports how many keys it holds', verified.keySet.keyCount > 0, true);

// ---------------------------------------------------------------------------
// 3. A rotated key set is not a forgery. Different fact, different report.
// ---------------------------------------------------------------------------
console.log('\n--- stale key set (rotation, not compromise) ---');
const stale = JSON.parse(verifyStatement(genuine, staleKeys));
check('kid is not in the stale set', stale.receipts[0].keyLookup, 'unknown-kid');
check('root signature never ran', stale.receipts[0].rootSignatureValid, null);
check('not reported as verified', stale.receipts[0].fullyVerified, false);

// ---------------------------------------------------------------------------
// 4. The binding check: easy to omit, fatal to omit.
//    payload-tampered.cose has a genuine receipt, a valid inclusion proof and a
//    verifying root signature. It is still not evidence about this payload.
// ---------------------------------------------------------------------------
console.log('\n--- payload tampered (binding check) ---');
const payloadTampered = JSON.parse(verifyStatement(read('payload-tampered.cose'), keys));
const ptReceipt = payloadTampered.receipts[0];
check('root signature still verifies', ptReceipt.rootSignatureValid, true);
check('receipt is NOT bound to this statement', ptReceipt.boundToStatement, false);
check('so nothing is verified', payloadTampered.anyReceiptVerified, false);
check('claim digest differs from genuine', payloadTampered.claimDigest !== PINNED.claimDigest, true);

// ---------------------------------------------------------------------------
// 5. A tampered receipt fails its root signature, but the statement is intact.
// ---------------------------------------------------------------------------
console.log('\n--- tampered receipt ---');
const tampered = JSON.parse(verifyStatement(read('tampered-statement.cose'), keys));
check('statement signature is untouched', tampered.signatureValid, true);
check('root signature fails', tampered.receipts[0].rootSignatureValid, false);
check('nothing verified', tampered.anyReceiptVerified, false);

// ---------------------------------------------------------------------------
// 6. An appended receipt must not veto a good artifact.
//    Receipts travel in the unprotected bucket, which no signature covers, so
//    anyone who handles the file can append one. If that flipped the verdict,
//    every mirror and CI cache would hold a veto. RFC 9943 7.1: at least one.
// ---------------------------------------------------------------------------
console.log('\n--- appended receipt ---');
const appended = JSON.parse(verifyStatement(read('appended-receipt.cose'), keys));
check('two receipt blobs arrived', appended.receiptsPresent, 2);
check('exactly one verified', appended.verifiedReceiptCount, 1);
check('the genuine one still counts', appended.anyReceiptVerified, true);

// ---------------------------------------------------------------------------
// 7. Hash envelope statements parse.
// ---------------------------------------------------------------------------
console.log('\n--- hash envelope ---');
const envelope = JSON.parse(inspectStatement(read('hash-envelope.cose')));
check('recognised as a hash envelope', envelope.isHashEnvelope, true);

// ---------------------------------------------------------------------------
// 8. Policy evaluation crosses the boundary without becoming a verdict.
//
//    The output carries per-assertion outcomes and the three aggregate
//    predicates, and deliberately no pass/fail for the statement. A page that
//    wants one has to decide it, the same way `decide()` does for the CLI.
// ---------------------------------------------------------------------------
console.log('\n--- policy evaluation ---');
const policies = join(here, '..', '..', '..', 'corpus', 'policies');
const policy = (name) => new Uint8Array(readFileSync(join(policies, name)));

// Pinned to the fixture's own registration time so the run does not change
// meaning as the wall clock advances. The `now` argument exists precisely so
// a caller can do this.
const registeredAt = receipt.registeredAt;
const AT_REGISTRATION = registeredAt + 60;

const satisfied = JSON.parse(evaluatePolicy(genuine, keys, policy('fixture-mst.json'), AT_REGISTRATION));
check('policy is identified in the result', satisfied.policyId, 'corpus/fixture-mst');
check('policy version is reported', satisfied.policyVersion, '1');
check('every assertion passed', satisfied.satisfied, true);
check('nothing failed', satisfied.failed, false);
check('nothing was unevaluable', satisfied.unevaluable, false);
check('four assertions were evaluated', satisfied.assertions.length, 4);
check('all outcomes are pass', satisfied.assertions.every((a) => a.outcome === 'pass'), true);
check('no verdict field is exposed', satisfied.verdict, undefined);

// A policy naming a transparency service this statement was not registered
// with. The receipt still verifies — the signature was never the question.
const wrongIssuer = JSON.parse(evaluatePolicy(genuine, keys, policy('wrong-issuer.json'), AT_REGISTRATION));
check('policy is not satisfied', wrongIssuer.satisfied, false);
check('and the reason is failure, not absence', wrongIssuer.failed, true);
check('not reported as unevaluable', wrongIssuer.unevaluable, false);
const issuerAssertion = wrongIssuer.assertions.find((a) => a.outcome === 'fail');
check('a failing assertion is named', issuerAssertion !== undefined, true);
// The detail string is what a UI shows next to the red row. If it does not
// name what was actually seen, the user is told "no" without being told why.
check('its detail names the observed issuer', issuerAssertion.detail.includes(ISSUER), true);

// ---------------------------------------------------------------------------
// 9. `fail` and `cannotEvaluate` stay distinct across the boundary.
//
//    Authored here rather than committed because the point is the shape of the
//    output, not the document: an assertion about a claim this statement never
//    made must not arrive as a failure.
// ---------------------------------------------------------------------------
console.log('\n--- unevaluable is not failure ---');
const svnPolicy = new TextEncoder().encode(JSON.stringify({
  policyId: 'harness/absent-claim',
  policyVersion: '1',
  assertions: { minSvn: 1 },
}));
const absent = JSON.parse(evaluatePolicy(genuine, keys, svnPolicy, AT_REGISTRATION));
check('the statement makes no SVN claim', verified.cwt.svn, null);
check('so the assertion cannot be evaluated', absent.assertions[0].outcome, 'cannotEvaluate');
check('which is not a failure', absent.failed, false);
check('but it is not satisfied either', absent.satisfied, false);
check('and it is reported as unevaluable', absent.unevaluable, true);

// ---------------------------------------------------------------------------
// 10. `now` is honoured, not ignored.
//     Same bytes, same policy, two clocks, two outcomes.
// ---------------------------------------------------------------------------
console.log('\n--- the caller supplies the clock ---');
const freshness = new TextEncoder().encode(JSON.stringify({
  policyId: 'harness/freshness',
  policyVersion: '1',
  assertions: { maxAgeDays: 30 },
}));
const fresh = JSON.parse(evaluatePolicy(genuine, keys, freshness, AT_REGISTRATION));
check('fresh at registration time', fresh.satisfied, true);
const aged = JSON.parse(evaluatePolicy(genuine, keys, freshness, registeredAt + 60 * 60 * 24 * 400));
check('stale 400 days later', aged.failed, true);

// A clock that is silently wrong would quietly change a freshness decision, so
// a nonsensical one is refused rather than truncated.
let badClock = false;
try {
  evaluatePolicy(genuine, keys, freshness, 1.5);
} catch {
  badClock = true;
}
check('a non-integral clock is rejected', badClock, true);

// ---------------------------------------------------------------------------
// 11. A malformed policy is an exception, not a finding.
//     Nothing was evaluated, so there is no result to render.
// ---------------------------------------------------------------------------
console.log('\n--- malformed policy ---');
let threw = false;
try {
  evaluatePolicy(genuine, keys, new TextEncoder().encode('{ not json'), AT_REGISTRATION);
} catch {
  threw = true;
}
check('parse failure raises rather than returning a decision', threw, true);

// ---------------------------------------------------------------------------
// 12. The payload is what the statement says, and a digest is not content.
// ---------------------------------------------------------------------------
console.log('\n--- payload ---');
const carried = JSON.parse(statementPayload(genuine));
check('not detached', carried.detached, false);
check('length agrees with the verified facts', carried.length, verified.payloadLength);
check('not a hash envelope', carried.hashEnvelope, null);
check('sha256 of the payload is not the claim digest',
  carried.sha256 !== PINNED.claimDigest, true);
check('text is decoded rather than handed back as base64', typeof carried.text, 'string');

// RFC 9995: the payload is a digest of the artifact. Emitting `sha256` here
// would be a hash of a hash — a plausible-looking value that identifies nothing
// and sits one field away from the artifact digest a reader is looking for.
const hashEnvelopePayload = JSON.parse(statementPayload(read('hash-envelope.cose')));
check('recognised as a hash envelope', hashEnvelopePayload.hashEnvelope !== null, true);
check('publishes the digest itself',
  typeof hashEnvelopePayload.hashEnvelope.digest, 'string');
check('names the algorithm that produced it',
  typeof hashEnvelopePayload.hashEnvelope.hashAlg, 'string');
check('and emits no hash of that hash', hashEnvelopePayload.sha256, undefined);
check('nor a text rendering of 32 opaque bytes', hashEnvelopePayload.text, undefined);

// ---------------------------------------------------------------------------
// 13. Binding answers a different question from verification: not "is this
//     statement genuine" but "is it about the file I am holding". The two fail
//     independently, and the third outcome — cannotCompare — must never be
//     collapsed into a mismatch, which would accuse an operator of shipping the
//     wrong artifact when the request was simply the wrong shape.
// ---------------------------------------------------------------------------
console.log('\n--- artifact binding ---');
const artifact = read('artifact.bin');
const badArtifact = read('bad-artifact.bin');

const boundResult = JSON.parse(bindArtifact(genuine, artifact, 'payload-bytes', 'artifact.bin'));
check('the artifact it describes is bound', boundResult.outcome, 'bound');
check('with a machine-stable reason', boundResult.reason, 'payloadIsArtifact');
check('the declared mode is echoed back', boundResult.mode, 'payload-bytes');
check('the artifact is named', boundResult.artifactName, 'artifact.bin');
check('and measured', boundResult.artifactLength, artifact.length);
check('detail says what was compared', boundResult.detail.includes('byte-identical'), true);

// The digest must be a real one, not a placeholder that happens to be a string.
check('the reported digest is genuinely sha-256 of those bytes',
  boundResult.artifactSha256,
  createHash('sha256').update(artifact).digest('hex'));

const mismatch = JSON.parse(bindArtifact(genuine, badArtifact, 'payload-bytes', 'bad-artifact.bin'));
check('a different file is a mismatch', mismatch.outcome, 'mismatch');
check('named as such', mismatch.reason, 'payloadIsNotArtifact');
check('while the statement itself still verifies', verified.signatureValid, true);

// RFC 9995: the payload is a digest, so the artifact is hashed with the
// algorithm the signer named rather than a default this build prefers.
const envelopeBytes = read('hash-envelope.cose');
const envelopeBound = JSON.parse(bindArtifact(
  envelopeBytes, read('hash-envelope-artifact.spdx.json'), 'payload-digest', 'sbom.spdx.json'));
check('a hash envelope binds to its preimage', envelopeBound.outcome, 'bound');
check('by digest rather than by bytes', envelopeBound.reason, 'digestIsArtifact');

const envelopeWrong = JSON.parse(bindArtifact(
  envelopeBytes, read('hash-envelope-bad-artifact.spdx.json'), 'payload-digest', 'other.json'));
check('and not to a different preimage', envelopeWrong.outcome, 'mismatch');

// Both directions of "the mode does not fit this statement". Neither is
// evidence about the artifact, so neither may be reported as a mismatch.
const envelopeAsBytes = JSON.parse(bindArtifact(envelopeBytes, artifact, 'payload-bytes', 'a'));
check('a digest payload compared as bytes cannot compare', envelopeAsBytes.outcome, 'cannotCompare');
check('and says why', envelopeAsBytes.reason, 'hashEnvelopeNeedsDigestMode');
check('offering no command-line remedy a browser cannot act on',
  envelopeAsBytes.detail.includes('--binding-mode'), false);

const plainAsDigest = JSON.parse(bindArtifact(genuine, artifact, 'payload-digest', 'a'));
check('a byte payload compared as a digest cannot compare', plainAsDigest.outcome, 'cannotCompare');
check('and says why', plainAsDigest.reason, 'notAHashEnvelope');

// The mode is always declared. An unknown one must be refused rather than
// quietly treated as either of the real ones.
let modeThrew = false;
try {
  bindArtifact(genuine, artifact, 'guess', 'a');
} catch {
  modeThrew = true;
}
check('an unknown mode is refused, not guessed', modeThrew, true);

// Prose that names nothing reads as though some unnamed file was compared.
const unnamed = JSON.parse(bindArtifact(genuine, artifact, 'payload-bytes', ''));
check('an unnamed artifact still reads as a sentence',
  unnamed.detail.includes('the artifact'), true);

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);

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
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  verifyStatement,
  inspectStatement,
  claimDigest,
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
const verified = JSON.parse(verifyStatement(genuine, keys, undefined));
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
// 2. Issuer scoping is applied before kid matching.
// ---------------------------------------------------------------------------
console.log('\n--- issuer scoping ---');
const scoped = JSON.parse(verifyStatement(genuine, keys, ISSUER));
check('correct issuer still verifies', scoped.receipts[0].fullyVerified, true);
check('key set reports as scoped', scoped.keySet.scoped, true);

const wrongIssuer = JSON.parse(
  verifyStatement(genuine, keys, 'contoso.confidential-ledger.azure.com'),
);
check('wrong issuer refuses the key', wrongIssuer.receipts[0].keyLookup, 'issuer-mismatch');
check('wrong issuer does not verify', wrongIssuer.receipts[0].fullyVerified, false);

// ---------------------------------------------------------------------------
// 3. A rotated key set is not a forgery. Different fact, different report.
// ---------------------------------------------------------------------------
console.log('\n--- stale key set (rotation, not compromise) ---');
const stale = JSON.parse(verifyStatement(genuine, staleKeys, undefined));
check('kid is not in the stale set', stale.receipts[0].keyLookup, 'unknown-kid');
check('root signature never ran', stale.receipts[0].rootSignatureValid, null);
check('not reported as verified', stale.receipts[0].fullyVerified, false);

// ---------------------------------------------------------------------------
// 4. The binding check: easy to omit, fatal to omit.
//    payload-tampered.cose has a genuine receipt, a valid inclusion proof and a
//    verifying root signature. It is still not evidence about this payload.
// ---------------------------------------------------------------------------
console.log('\n--- payload tampered (binding check) ---');
const payloadTampered = JSON.parse(verifyStatement(read('payload-tampered.cose'), keys, undefined));
const ptReceipt = payloadTampered.receipts[0];
check('root signature still verifies', ptReceipt.rootSignatureValid, true);
check('receipt is NOT bound to this statement', ptReceipt.boundToStatement, false);
check('so nothing is verified', payloadTampered.anyReceiptVerified, false);
check('claim digest differs from genuine', payloadTampered.claimDigest !== PINNED.claimDigest, true);

// ---------------------------------------------------------------------------
// 5. A tampered receipt fails its root signature, but the statement is intact.
// ---------------------------------------------------------------------------
console.log('\n--- tampered receipt ---');
const tampered = JSON.parse(verifyStatement(read('tampered-statement.cose'), keys, undefined));
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
const appended = JSON.parse(verifyStatement(read('appended-receipt.cose'), keys, undefined));
check('two receipt blobs arrived', appended.receiptsPresent, 2);
check('exactly one verified', appended.verifiedReceiptCount, 1);
check('the genuine one still counts', appended.anyReceiptVerified, true);

// ---------------------------------------------------------------------------
// 7. Hash envelope statements parse.
// ---------------------------------------------------------------------------
console.log('\n--- hash envelope ---');
const envelope = JSON.parse(inspectStatement(read('hash-envelope.cose')));
check('recognised as a hash envelope', envelope.isHashEnvelope, true);

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);

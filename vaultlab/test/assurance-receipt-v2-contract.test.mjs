import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  CHALLENGE_BYTES,
  RECEIPT_ID_BYTES,
  isCanonicalBase64Url,
  newReceiptId,
  validSourceRevision,
} from '../../api/private/assurance/assurance-receipt-contract.mjs';

test('canonical 32-byte challenges are accepted and malformed variants fail closed', () => {
  const challenge = Buffer.alloc(CHALLENGE_BYTES, 0xa1).toString('base64url');
  assert.equal(isCanonicalBase64Url(challenge, CHALLENGE_BYTES), true);
  assert.equal(isCanonicalBase64Url(`${challenge}=`, CHALLENGE_BYTES), false);
  assert.equal(isCanonicalBase64Url(challenge.slice(1), CHALLENGE_BYTES), false);
  assert.equal(isCanonicalBase64Url('not/canonical', CHALLENGE_BYTES), false);
  assert.equal(isCanonicalBase64Url('', CHALLENGE_BYTES), false);
});

test('receipt identifiers are canonical, correctly sized and unique in the sample', () => {
  const identifiers = Array.from({ length: 512 }, () => newReceiptId());
  assert.equal(identifiers.every((value) => isCanonicalBase64Url(value, RECEIPT_ID_BYTES)), true);
  assert.equal(new Set(identifiers).size, identifiers.length);
});

test('only exact lowercase 40-character source revisions are accepted', () => {
  assert.equal(validSourceRevision('a'.repeat(40)), true);
  assert.equal(validSourceRevision('0'.repeat(40)), true);
  assert.equal(validSourceRevision('A'.repeat(40)), false);
  assert.equal(validSourceRevision('a'.repeat(39)), false);
  assert.equal(validSourceRevision('a'.repeat(41)), false);
  assert.equal(validSourceRevision(` ${'a'.repeat(40)}`), false);
});

test('the issuer is wired only to v2 challenge, revision and no-store contracts', async () => {
  const source = await readFile(
    new URL('../../api/private/assurance/receipt.js', import.meta.url),
    'utf8',
  );
  assert.match(source, /osoix\.assurance-signing-request\.v2/u);
  assert.match(source, /osoix\.assurance-receipt\.v2/u);
  assert.doesNotMatch(source, /osoix\.assurance-(?:signing-request|receipt)\.v1/u);
  assert.match(source, /x-osoix-challenge/u);
  assert.match(source, /sourceRevision: runtimeIdentity\.evidence\.sourceRevision/u);
  assert.match(source, /private, no-store/u);
  assert.match(source, /Vary', 'Authorization, x-osoix-purpose, x-osoix-challenge'/u);
  assert.match(source, /reason: 'signer_unavailable'/u);
});

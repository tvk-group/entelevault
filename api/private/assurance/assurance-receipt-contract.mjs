export const CHALLENGE_BYTES = 32;
export const RECEIPT_ID_BYTES = 18;

const SOURCE_REVISION_PATTERN = /^[0-9a-f]{40}$/u;

export function isCanonicalBase64Url(value, expectedBytes) {
  if (
    typeof value !== 'string'
    || !Number.isSafeInteger(expectedBytes)
    || expectedBytes <= 0
    || !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    return false;
  }
  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.byteLength === expectedBytes && decoded.toString('base64url') === value;
  } catch {
    return false;
  }
}

export function validSourceRevision(value) {
  return typeof value === 'string' && SOURCE_REVISION_PATTERN.test(value);
}

export function newReceiptId() {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(RECEIPT_ID_BYTES))).toString(
    'base64url',
  );
}

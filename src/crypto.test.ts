import { createHash } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import { webCrypto } from './crypto';
import { createPkceRequest } from './pkce';

describe('webCrypto', () => {
  test('rend le nombre d\'octets demandé, différents à chaque appel', async () => {
    const [a, b] = await Promise.all([webCrypto.randomBytes(64), webCrypto.randomBytes(64)]);

    expect(a).toHaveLength(64);
    expect(b).toHaveLength(64);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  test('calcule le SHA-256 en base64 standard (le vecteur de la RFC 7636)', async () => {
    const digest = await webCrypto.sha256Base64('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');

    expect(digest).toBe(createHash('sha256').update('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk').digest('base64'));
  });

  test('une demande PKCE complète avec Web Crypto', async () => {
    const request = await createPkceRequest(webCrypto);

    expect(request.verifier).toHaveLength(86);
    expect(request.challenge).toBe(createHash('sha256').update(request.verifier).digest('base64url'));
  });
});

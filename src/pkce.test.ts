import { createHash } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import type { CryptoProvider } from './crypto';
import { base64ToBase64Url, base64UrlEncode } from './encoding';
import { createPkceRequest } from './pkce';

// RFC 7636, annexe B : la suite d'octets, son encodage (le vérificateur) et l'empreinte S256 attendue.
const rfcOctets = Uint8Array.from([
  116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91,
  88, 5, 88, 83, 132, 141, 121,
]);
const rfcVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const rfcChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

function cryptoWith(...random: Uint8Array[]): CryptoProvider {
  const queue = [...random];

  return {
    randomBytes: async () => queue.shift() ?? new Uint8Array(0),
    sha256Base64: async (value) => createHash('sha256').update(value).digest('base64'),
  };
}

describe('base64UrlEncode', () => {
  test("encode la suite d'octets de la RFC 7636 en son vérificateur", () => {
    expect(base64UrlEncode(rfcOctets)).toBe(rfcVerifier);
  });

  test("n'ajoute jamais de remplissage et n'emploie ni + ni /", () => {
    for (const length of [1, 2, 3, 4, 5, 63, 64]) {
      const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + 251) % 256);
      const encoded = base64UrlEncode(bytes);

      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(encoded).toBe(Buffer.from(bytes).toString('base64url'));
    }
  });
});

describe('base64ToBase64Url', () => {
  test('convertit une base64 standard', () => {
    expect(base64ToBase64Url('a+b/c===')).toBe('a-b_c');
  });
});

describe('createPkceRequest', () => {
  test("l'empreinte S256 du vérificateur de la RFC est celle de la RFC", async () => {
    const request = await createPkceRequest(cryptoWith(rfcOctets, Uint8Array.from([1, 2, 3, 4])));

    expect(request.verifier).toBe(rfcVerifier);
    expect(request.challenge).toBe(rfcChallenge);
    expect(request.state).toBe(base64UrlEncode(Uint8Array.from([1, 2, 3, 4])));
  });

  test("l'empreinte correspond au vérificateur pour 64 octets aléatoires", async () => {
    const random = Uint8Array.from({ length: 64 }, (_, index) => (index * 91 + 13) % 256);
    const request = await createPkceRequest(cryptoWith(random, random.slice(0, 16)));

    expect(request.verifier).toHaveLength(86);
    expect(request.challenge).toBe(createHash('sha256').update(request.verifier).digest('base64url'));
  });
});

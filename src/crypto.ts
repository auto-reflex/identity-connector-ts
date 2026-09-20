/**
 * Ce dont PKCE a besoin de la plateforme. Hermes (React Native) n'a pas `crypto.subtle` : l'application Expo fournit
 * `expo-crypto`, un navigateur ou Node utilisent `webCrypto`.
 */
export type CryptoProvider = {
  /** Octets aléatoires cryptographiquement sûrs. */
  randomBytes: (length: number) => Promise<Uint8Array>;
  /** SHA-256 de la chaîne (UTF-8), en base64 standard. */
  sha256Base64: (value: string) => Promise<string>;
};

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary);
}

/** Fournisseur fondé sur Web Crypto : navigateurs, Node 20+, Next.js (runtime Node ou Edge). */
export const webCrypto: CryptoProvider = {
  async randomBytes(length) {
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
  },

  async sha256Base64(value) {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));

    return bytesToBase64(new Uint8Array(digest));
  },
};

import type { CryptoProvider } from './crypto';
import { base64ToBase64Url, base64UrlEncode } from './encoding';

export type PkceRequest = {
  verifier: string;
  challenge: string;
  state: string;
};

/** Vérificateur PKCE (RFC 7636, 86 caractères), son empreinte SHA-256 (méthode `S256`) et un `state` aléatoire. */
export async function createPkceRequest(crypto: CryptoProvider): Promise<PkceRequest> {
  const [verifierBytes, stateBytes] = await Promise.all([crypto.randomBytes(64), crypto.randomBytes(16)]);
  const verifier = base64UrlEncode(verifierBytes);

  return {
    verifier,
    challenge: base64ToBase64Url(await crypto.sha256Base64(verifier)),
    state: base64UrlEncode(stateBytes),
  };
}

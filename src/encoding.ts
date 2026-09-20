const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Base64 « URL-safe » sans remplissage (RFC 4648 §5), telle que PKCE l'exige (RFC 7636 §4). */
export function base64UrlEncode(bytes: Uint8Array): string {
  let output = '';

  for (let index = 0; index < bytes.length; index += 3) {
    const chunk = (bytes[index] << 16) | ((bytes[index + 1] ?? 0) << 8) | (bytes[index + 2] ?? 0);
    const remaining = bytes.length - index;

    output += alphabet[(chunk >> 18) & 63] + alphabet[(chunk >> 12) & 63];
    if (remaining > 1) output += alphabet[(chunk >> 6) & 63];
    if (remaining > 2) output += alphabet[chunk & 63];
  }

  return output;
}

/** Convertit une base64 standard (`+`, `/`, `=`) en base64 URL-safe. */
export function base64ToBase64Url(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

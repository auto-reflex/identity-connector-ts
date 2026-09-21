/**
 * Session d'une application web côté serveur (Next.js, Node) : client confidentiel dont les tokens vivent dans des cookies
 * httpOnly, jamais dans le navigateur. Le paquet ne connaît aucun framework : l'application fournit un `CookieJar`
 * (`cookies()` de Next dans un route handler ou une action, la requête et la réponse dans `proxy.ts`).
 */
import { IdentityError, type IdentityClient, type IdentityTokens } from './client';
import type { CryptoProvider } from './crypto';
import { base64UrlEncode } from './encoding';
import { createPkceRequest } from './pkce';
import { createTokenManager, type AccessTokenOptions, type TokenStore } from './token-manager';

export type CookieOptions = {
  httpOnly: true;
  secure: boolean;
  sameSite: 'lax';
  path: '/';
  /** Durée de vie en secondes ; sans elle, le cookie est un cookie de session. */
  maxAge?: number;
};

export type CookieJar = {
  get: (name: string) => string | undefined;
  set: (name: string, value: string, options: CookieOptions) => void;
  delete: (name: string) => void;
};

export type WebSessionOptions = {
  client: IdentityClient;
  jar: CookieJar;
  crypto: CryptoProvider;
  /** `true` en production (HTTPS) : les cookies ne voyagent que chiffrés. */
  secure: boolean;
  /** Préfixe des cookies (défaut `identity`) : `identity_access`, `identity_refresh`, `identity_expires`, `identity_pkce`, `identity_relogin`. */
  cookiePrefix?: string;
  /** Durée de vie des cookies de tokens, en secondes : celle du refresh token d'Identity (défaut 30 jours). */
  sessionSeconds?: number;
  /** Délai laissé à la révocation à la déconnexion, en millisecondes (défaut 3 000). */
  revokeTimeoutMs?: number;
  /** Partage les refresh simultanés du même token (voir `createSharedRefresher`). Par défaut, un refresher partagé propre à cette session. */
  refresher?: Pick<IdentityClient, 'refresh'>;
  now?: () => number;
};

export type PendingSignIn = { state: string; verifier: string; returnTo: string };

const PKCE_SECONDS = 600;
const RELOGIN_SECONDS = 86_400;

/** Une adresse de retour interne seulement : jamais de redirection vers un autre site après la connexion. */
export function safeReturnTo(value: string | null | undefined, fallback = '/'): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return fallback;

  return value;
}

/**
 * Le refresh token d'Identity est à usage unique. Sur un serveur, la même page déclenche plusieurs requêtes en parallèle
 * (proxy, composants serveur, appels du navigateur) portant le même refresh token périmé : la première le consomme, les
 * autres seraient refusées (`invalid_grant`) et déconnecteraient à tort. Les refresh du même token sont donc partagés
 * pendant `ttlMs` (30 s) dans ce processus : tous reçoivent les mêmes nouveaux tokens. Un échec n'est jamais retenu.
 */
export function createSharedRefresher(
  client: Pick<IdentityClient, 'refresh'>,
  { ttlMs = 30_000 }: { ttlMs?: number } = {},
): Pick<IdentityClient, 'refresh'> {
  const shared = new Map<string, Promise<IdentityTokens>>();

  return {
    refresh(refreshToken: string): Promise<IdentityTokens> {
      const existing = shared.get(refreshToken);

      if (existing) return existing;

      const request = client.refresh(refreshToken);
      shared.set(refreshToken, request);
      request.then(
        () => {
          const timer = setTimeout(() => shared.delete(refreshToken), ttlMs);
          (timer as { unref?: () => void }).unref?.();
        },
        () => shared.delete(refreshToken),
      );

      return request;
    },
  };
}

/** Un `TokenStore` sur trois cookies httpOnly : un JWT RS256 et un refresh token seraient trop gros ensemble pour un cookie de 4 Ko. */
export function createCookieTokenStore(
  jar: CookieJar,
  { secure, prefix = 'identity', sessionSeconds = 30 * 86_400 }: { secure: boolean; prefix?: string; sessionSeconds?: number },
): TokenStore {
  const names = { access: `${prefix}_access`, refresh: `${prefix}_refresh`, expires: `${prefix}_expires` };
  const options: CookieOptions = { httpOnly: true, secure, sameSite: 'lax', path: '/', maxAge: sessionSeconds };

  return {
    async read() {
      const accessToken = jar.get(names.access);
      const refreshToken = jar.get(names.refresh);
      const expiresAt = Number(jar.get(names.expires));

      if (!accessToken || !refreshToken || !Number.isFinite(expiresAt)) return null;

      return { accessToken, refreshToken, expiresAt };
    },

    async write(tokens) {
      jar.set(names.access, tokens.accessToken, options);
      jar.set(names.refresh, tokens.refreshToken, options);
      jar.set(names.expires, String(tokens.expiresAt), options);
    },

    async clear() {
      Object.values(names).forEach((name) => jar.delete(name));
    },
  };
}

export function createWebSession({
  client,
  jar,
  crypto,
  secure,
  cookiePrefix = 'identity',
  sessionSeconds,
  revokeTimeoutMs = 3_000,
  refresher,
  now = Date.now,
}: WebSessionOptions) {
  const pkceCookie = `${cookiePrefix}_pkce`;
  const reloginCookie = `${cookiePrefix}_relogin`;
  const store = createCookieTokenStore(jar, { secure, prefix: cookiePrefix, sessionSeconds });
  const tokenManager = createTokenManager({ store, client: refresher ?? createSharedRefresher(client), now });

  function readPending(): PendingSignIn | null {
    const raw = jar.get(pkceCookie);

    if (!raw) return null;

    try {
      const value = JSON.parse(atob(raw.replace(/-/g, '+').replace(/_/g, '/'))) as Partial<PendingSignIn>;

      return typeof value.state === 'string' && typeof value.verifier === 'string' && typeof value.returnTo === 'string'
        ? { state: value.state, verifier: value.verifier, returnTo: value.returnTo }
        : null;
    } catch {
      return null;
    }
  }

  return {
    tokenManager,

    /**
     * Prépare la connexion : mémorise PKCE et l'adresse de retour dans un cookie court, et rend l'adresse d'Identity vers
     * laquelle rediriger. Après une déconnexion volontaire, les identifiants sont redemandés (changement de compte).
     */
    async beginSignIn({ returnTo }: { returnTo?: string | null } = {}): Promise<string> {
      const pkce = await createPkceRequest(crypto);
      const pending: PendingSignIn = { state: pkce.state, verifier: pkce.verifier, returnTo: safeReturnTo(returnTo) };
      const encoded = base64UrlEncode(new TextEncoder().encode(JSON.stringify(pending)));

      jar.set(pkceCookie, encoded, { httpOnly: true, secure, sameSite: 'lax', path: '/', maxAge: PKCE_SECONDS });

      return client.authorizeUrl({ state: pkce.state, codeChallenge: pkce.challenge, forceLogin: jar.get(reloginCookie) === '1' });
    },

    /**
     * Termine la connexion au retour d'Identity : vérifie `state`, échange le code (avec le secret du client) et pose les
     * cookies de session. `callbackUrl` est l'adresse complète reçue. Rend l'adresse interne où renvoyer la personne.
     *
     * @throws IdentityError `invalid_state` sans connexion en cours ou avec un `state` différent, `access_denied`, etc.
     */
    async finishSignIn(callbackUrl: string): Promise<{ returnTo: string }> {
      const pending = readPending();

      jar.delete(pkceCookie);

      if (!pending) throw new IdentityError('Aucune connexion en cours : recommence.', 'invalid_state');

      const code = client.parseCallback(callbackUrl, pending.state);

      await tokenManager.set(await client.exchangeCode(code, pending.verifier));
      jar.delete(reloginCookie);

      return { returnTo: safeReturnTo(pending.returnTo) };
    },

    async hasSession(): Promise<boolean> {
      return (await tokenManager.current()) !== null;
    },

    /**
     * Le token d'accès à présenter à l'API, renouvelé s'il expire. Dans un composant serveur les cookies ne s'écrivent pas :
     * le renouvellement a lieu dans `proxy.ts` (avec un `CookieJar` sur la réponse), et ici on lit un token frais.
     */
    getAccessToken(options?: AccessTokenOptions): Promise<string> {
      return tokenManager.getAccessToken(options);
    },

    /**
     * Efface les cookies tout de suite, marque la prochaine connexion comme « à refaire » (`prompt=login`) et révoque le
     * refresh token à Identity, sans attendre plus de `revokeTimeoutMs` : Identity injoignable ne bloque pas la déconnexion.
     */
    async signOut(): Promise<void> {
      const tokens = await tokenManager.current();

      await tokenManager.clear();
      jar.set(reloginCookie, '1', { httpOnly: true, secure, sameSite: 'lax', path: '/', maxAge: RELOGIN_SECONDS });

      if (!tokens) return;

      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<void>((resolve) => {
        timer = setTimeout(resolve, revokeTimeoutMs);
      });

      try {
        await Promise.race([client.revoke(tokens.refreshToken).catch(() => undefined), timeout]);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

export type WebSession = ReturnType<typeof createWebSession>;

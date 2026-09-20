import { IdentityError, type IdentityClient, type IdentityTokens } from './client';

export type TokenStore = {
  read: () => Promise<IdentityTokens | null>;
  write: (tokens: IdentityTokens) => Promise<void>;
  clear: () => Promise<void>;
};

export type TokenManagerOptions = {
  store: TokenStore;
  client: Pick<IdentityClient, 'refresh'>;
  now?: () => number;
  /** Un token qui expire dans moins de ce délai est renouvelé avant l'appel (millisecondes). */
  skewMs?: number;
};

/** Aucune session : la personne n'est pas connectée (ou vient de perdre sa session). */
export class NoSessionError extends Error {
  constructor() {
    super('Aucune session AutoReflex.');
    this.name = 'NoSessionError';
  }
}

export type AccessTokenOptions = {
  /**
   * Le token que l'API vient de refuser (401). Si un autre appel l'a déjà remplacé, on renvoie le nouveau sans
   * refaire de refresh ; sinon on en force un.
   */
  rejected?: string;
};

/**
 * Point de passage unique du token d'accès. Le refresh token d'Identity est à usage unique : deux refresh
 * simultanés du même token feraient échouer le second, donc un refresh en cours est partagé par tous les appels.
 */
export function createTokenManager({ store, client, now = Date.now, skewMs = 60_000 }: TokenManagerOptions) {
  let cached: IdentityTokens | null | undefined;
  let inflight: Promise<IdentityTokens> | null = null;
  const lostListeners = new Set<() => void>();

  async function current(): Promise<IdentityTokens | null> {
    if (cached === undefined) cached = await store.read();

    return cached;
  }

  async function lose(): Promise<void> {
    cached = null;
    await store.clear();
    lostListeners.forEach((listener) => listener());
  }

  function refresh(tokens: IdentityTokens): Promise<IdentityTokens> {
    inflight ??= (async () => {
      try {
        const fresh = await client.refresh(tokens.refreshToken);
        // Écrit avant tout : l'ancien refresh token est déjà révoqué côté Identity.
        await store.write(fresh);
        cached = fresh;

        return fresh;
      } catch (error) {
        if (error instanceof IdentityError && error.code === 'invalid_grant') await lose();
        throw error;
      } finally {
        inflight = null;
      }
    })();

    return inflight;
  }

  return {
    /**
     * @throws NoSessionError sans session
     * @throws IdentityError `network_error` ou `server_error` (session conservée), `invalid_grant` (session perdue)
     */
    async getAccessToken({ rejected }: AccessTokenOptions = {}): Promise<string> {
      const tokens = await current();

      if (!tokens) throw new NoSessionError();

      const stale = rejected !== undefined && tokens.accessToken === rejected;
      const expiring = tokens.expiresAt - now() <= skewMs;

      if (!stale && !expiring) return tokens.accessToken;

      return (await refresh(tokens)).accessToken;
    },

    async current(): Promise<IdentityTokens | null> {
      return current();
    },

    /** À la connexion : les tokens remplacent tout ce qui restait. */
    async set(tokens: IdentityTokens): Promise<void> {
      await store.write(tokens);
      cached = tokens;
    },

    /** À la déconnexion volontaire : efface sans notifier (l'appelant met déjà la session à jour). */
    async clear(): Promise<void> {
      cached = null;
      await store.clear();
    },

    /** Notifie la perte de session provoquée par Identity (refresh refusé). Renvoie la fonction de désinscription. */
    onSessionLost(listener: () => void): () => void {
      lostListeners.add(listener);

      return () => lostListeners.delete(listener);
    },
  };
}

export type TokenManager = ReturnType<typeof createTokenManager>;

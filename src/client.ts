/**
 * Client OAuth2 d'AutoReflex Identity : Authorization Code + PKCE, refresh à rotation, révocation. Aucune dépendance
 * de plateforme (React Native, navigateur, Node) : uniquement `fetch`, pour rester vérifiable hors appareil.
 *
 * Identity publie ses endpoints dans les métadonnées OAuth 2.0. Le document est chargé une fois par session du
 * client ; l'émetteur configuré doit correspondre exactement à celui annoncé et à celui des tokens.
 */

export type IdentityTokens = {
  accessToken: string;
  refreshToken: string;
  /** Instant d'expiration de l'access token, en millisecondes. */
  expiresAt: number;
};

export type IdentityErrorCode =
  /** Refresh token refusé (révoqué, expiré, déjà utilisé) : la session est perdue. */
  | 'invalid_grant'
  /** Identity injoignable : la session reste valable, on réessaiera. */
  | 'network_error'
  /** Erreur temporaire côté Identity (5xx, limite de débit). */
  | 'server_error'
  /** La personne a refusé l'autorisation. */
  | 'access_denied'
  /** La réponse ne correspond pas à la demande (`state` différent). */
  | 'invalid_state'
  | 'invalid_response'
  | 'rejected';

export class IdentityError extends Error {
  constructor(
    message: string,
    readonly code: IdentityErrorCode,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'IdentityError';
  }
}

export type IdentityClientConfig = {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  uiLocales?: string;
  fetch?: typeof fetch;
  now?: () => number;
  /** Délai d'attente de chaque appel à Identity, en millisecondes. */
  timeoutMs?: number;
};

export type AuthorizeOptions = {
  state: string;
  codeChallenge: string;
  /** Force l'écran de connexion même si une session existe dans le navigateur (changement de compte). */
  forceLogin?: boolean;
};

type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
};

type AuthorizationServerMetadataPayload = {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  revocation_endpoint?: string;
};

type AuthorizationServerMetadata = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  revocationEndpoint: string;
};

const defaultLifetimeSeconds = 900;

/**
 * Sur iOS, un `fetch` vers une adresse injoignable ne rend jamais la main : sans ce délai, un démarrage, une
 * déconnexion ou un renouvellement de jeton sans réseau resteraient bloqués. Un délai dépassé est une coupure réseau.
 */
const defaultTimeoutMs = 15_000;

function formBody(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

/** Lit la requête d'une URL de retour (`monapp://oauth/callback?code=…&state=…`) sans dépendre de `URL`. */
export function parseQuery(url: string): Record<string, string> {
  const query = url.split('#')[0].split('?')[1] ?? '';
  const values: Record<string, string> = {};

  query.split('&').forEach((pair) => {
    if (pair === '') return;

    const [key, ...rest] = pair.split('=');
    values[decodeURIComponent(key.replace(/\+/g, ' '))] = decodeURIComponent(rest.join('=').replace(/\+/g, ' '));
  });

  return values;
}

export function createIdentityClient(config: IdentityClientConfig) {
  const issuer = config.issuer.replace(/\/$/, '');
  const request = config.fetch ?? fetch;
  const now = config.now ?? Date.now;
  const timeoutMs = config.timeoutMs ?? defaultTimeoutMs;
  let metadataRequest: Promise<AuthorizationServerMetadata> | null = null;

  async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      return await request(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  async function fetchMetadata(): Promise<AuthorizationServerMetadata> {
    let response: Response;

    try {
      response = await fetchWithTimeout(`${issuer}/.well-known/oauth-authorization-server`, {
        headers: { Accept: 'application/json' },
      });
    } catch {
      throw new IdentityError("Impossible de joindre AutoReflex. Vérifie ta connexion.", 'network_error');
    }

    let payload: AuthorizationServerMetadataPayload;

    try {
      payload = (await response.json()) as AuthorizationServerMetadataPayload;
    } catch {
      throw new IdentityError(
        'La configuration OAuth d’AutoReflex est illisible.',
        response.status >= 500 ? 'server_error' : 'invalid_response',
        response.status,
      );
    }

    if (!response.ok) {
      throw new IdentityError(
        'La configuration OAuth d’AutoReflex est indisponible.',
        response.status >= 500 || response.status === 429 ? 'server_error' : 'rejected',
        response.status,
      );
    }

    if (
      payload.issuer?.replace(/\/$/, '') !== issuer ||
      !payload.authorization_endpoint ||
      !payload.token_endpoint ||
      !payload.revocation_endpoint
    ) {
      throw new IdentityError('La configuration OAuth d’AutoReflex est incomplète ou incohérente.', 'invalid_response');
    }

    return {
      issuer,
      authorizationEndpoint: payload.authorization_endpoint,
      tokenEndpoint: payload.token_endpoint,
      revocationEndpoint: payload.revocation_endpoint,
    };
  }

  async function metadata(): Promise<AuthorizationServerMetadata> {
    metadataRequest ??= fetchMetadata().catch((error: unknown) => {
      metadataRequest = null;
      throw error;
    });

    return metadataRequest;
  }

  async function post(endpoint: string, params: Record<string, string>): Promise<Response> {
    try {
      return await fetchWithTimeout(endpoint, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formBody(params),
      });
    } catch {
      throw new IdentityError("Impossible de joindre AutoReflex. Vérifie ta connexion.", 'network_error');
    }
  }

  async function tokens(params: Record<string, string>): Promise<IdentityTokens> {
    const { tokenEndpoint } = await metadata();
    const response = await post(tokenEndpoint, params);
    let payload: TokenResponse;

    try {
      payload = (await response.json()) as TokenResponse;
    } catch {
      throw new IdentityError(
        'La réponse d’AutoReflex est illisible.',
        response.status >= 500 ? 'server_error' : 'invalid_response',
        response.status,
      );
    }

    if (!response.ok) {
      const message = payload.error_description ?? 'AutoReflex a refusé la demande.';

      if (payload.error === 'invalid_grant') throw new IdentityError(message, 'invalid_grant', response.status);
      if (response.status >= 500 || response.status === 429) throw new IdentityError(message, 'server_error', response.status);

      throw new IdentityError(message, 'rejected', response.status);
    }

    if (!payload.access_token || !payload.refresh_token) {
      throw new IdentityError('La réponse d’AutoReflex est incomplète.', 'invalid_response', response.status);
    }

    return {
      accessToken: payload.access_token,
      refreshToken: payload.refresh_token,
      expiresAt: now() + (payload.expires_in ?? defaultLifetimeSeconds) * 1000,
    };
  }

  return {
    issuer,
    redirectUri: config.redirectUri,

    /** Adresse à ouvrir dans le navigateur du système. */
    async authorizeUrl({ state, codeChallenge, forceLogin = false }: AuthorizeOptions): Promise<string> {
      const { authorizationEndpoint } = await metadata();
      const params: Record<string, string> = {
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        response_type: 'code',
        scope: config.scope,
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        ...(config.uiLocales ? { ui_locales: config.uiLocales } : {}),
        ...(forceLogin ? { prompt: 'login' } : {}),
      };

      return `${authorizationEndpoint}?${formBody(params)}`;
    },

    /** Extrait le code du retour d'Identity, après avoir vérifié `state`. */
    parseCallback(url: string, expectedState: string): string {
      const query = parseQuery(url);

      if (query.error === 'access_denied') {
        throw new IdentityError('L’accès a été refusé.', 'access_denied');
      }

      if (query.error) {
        throw new IdentityError(query.error_description ?? 'AutoReflex a refusé la demande.', 'rejected');
      }

      if (query.state !== expectedState) {
        throw new IdentityError('La réponse d’AutoReflex ne correspond pas à la demande.', 'invalid_state');
      }

      if (!query.code) {
        throw new IdentityError('La réponse d’AutoReflex ne contient pas de code.', 'invalid_response');
      }

      return query.code;
    },

    exchangeCode(code: string, codeVerifier: string): Promise<IdentityTokens> {
      return tokens({
        grant_type: 'authorization_code',
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        code,
        code_verifier: codeVerifier,
      });
    },

    /** La rotation invalide l'ancien refresh token : le résultat doit être conservé avant toute autre chose. */
    refresh(refreshToken: string): Promise<IdentityTokens> {
      return tokens({ grant_type: 'refresh_token', client_id: config.clientId, refresh_token: refreshToken });
    },

    /** Révoque le token et son jumeau. Identity répond 200 même pour un token inconnu. */
    async revoke(token: string): Promise<void> {
      const { revocationEndpoint } = await metadata();
      await post(revocationEndpoint, { client_id: config.clientId, token });
    },
  };
}

export type IdentityClient = ReturnType<typeof createIdentityClient>;

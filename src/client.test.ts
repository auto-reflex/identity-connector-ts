import { describe, expect, test, vi } from 'vitest';

import { createIdentityClient, IdentityError, parseQuery } from './client';

const issuer = 'http://identity.test';
const config = {
  issuer,
  clientId: 'example-mobile',
  redirectUri: 'exampleapp://oauth/callback',
  scope: 'profile email example:access',
  uiLocales: 'fr',
};
const metadata = {
  issuer,
  authorization_endpoint: `${issuer}/oauth/authorize`,
  token_endpoint: `${issuer}/oauth/token`,
  revocation_endpoint: `${issuer}/oauth/revoke`,
};

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function clientWith(handler: Handler, now = () => 1_000_000) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchMock = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });

    if (url.endsWith('/.well-known/oauth-authorization-server')) return json(metadata);

    return handler(url, init);
  }) as typeof fetch;

  return { client: createIdentityClient({ ...config, fetch: fetchMock, now }), calls };
}

const tokenBody = { access_token: 'access-1', refresh_token: 'refresh-1', expires_in: 900 };

describe('parseQuery', () => {
  test('lit la requête d\'un retour, sans dépendre de URL', () => {
    expect(parseQuery('exampleapp://oauth/callback?code=abc%20d&state=x+y#fragment')).toEqual({ code: 'abc d', state: 'x y' });
    expect(parseQuery('exampleapp://oauth/callback')).toEqual({});
  });
});

describe('authorizeUrl', () => {
  test('demande le code avec PKCE S256, les scopes du produit et la langue', async () => {
    const { client } = clientWith(() => json({}));
    const url = new URL(await client.authorizeUrl({ state: 'st', codeChallenge: 'ch' }));

    expect(`${url.origin}${url.pathname}`).toBe(`${issuer}/oauth/authorize`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: 'example-mobile',
      redirect_uri: 'exampleapp://oauth/callback',
      response_type: 'code',
      scope: 'profile email example:access',
      state: 'st',
      code_challenge: 'ch',
      code_challenge_method: 'S256',
      ui_locales: 'fr',
    });
  });

  test('ajoute prompt=login quand la connexion est forcée (changement de compte)', async () => {
    const { client } = clientWith(() => json({}));
    const url = new URL(await client.authorizeUrl({ state: 'st', codeChallenge: 'ch', forceLogin: true }));

    expect(url.searchParams.get('prompt')).toBe('login');
  });

  test('refuse des métadonnées dont l\'émetteur n\'est pas celui configuré', async () => {
    const fetchMock = (async () => json({ ...metadata, issuer: 'http://autre.test' })) as typeof fetch;
    const client = createIdentityClient({ ...config, fetch: fetchMock });

    await expect(client.authorizeUrl({ state: 's', codeChallenge: 'c' })).rejects.toMatchObject({ code: 'invalid_response' });
  });

  test('ne charge les métadonnées qu\'une fois', async () => {
    const { client, calls } = clientWith(() => json({}));

    await client.authorizeUrl({ state: 'a', codeChallenge: 'a' });
    await client.authorizeUrl({ state: 'b', codeChallenge: 'b' });

    expect(calls.filter((call) => call.url.includes('.well-known'))).toHaveLength(1);
  });
});

describe('parseCallback', () => {
  const { client } = clientWith(() => json({}));

  test('rend le code quand le state correspond', () => {
    expect(client.parseCallback('exampleapp://oauth/callback?code=the-code&state=st', 'st')).toBe('the-code');
  });

  test('refuse un state différent', () => {
    expect(() => client.parseCallback('exampleapp://oauth/callback?code=c&state=autre', 'st')).toThrow(
      expect.objectContaining({ code: 'invalid_state' }),
    );
  });

  test('distingue le refus de la personne des autres erreurs', () => {
    expect(() => client.parseCallback('exampleapp://oauth/callback?error=access_denied&state=st', 'st')).toThrow(
      expect.objectContaining({ code: 'access_denied' }),
    );
    expect(() => client.parseCallback('exampleapp://oauth/callback?error=server_error&state=st', 'st')).toThrow(
      expect.objectContaining({ code: 'rejected' }),
    );
  });

  test('refuse un retour sans code', () => {
    expect(() => client.parseCallback('exampleapp://oauth/callback?state=st', 'st')).toThrow(
      expect.objectContaining({ code: 'invalid_response' }),
    );
  });
});

describe('exchangeCode et refresh', () => {
  test('échangent contre des jetons dont l\'échéance est calculée sur l\'horloge du client', async () => {
    const { client, calls } = clientWith(() => json(tokenBody));

    const tokens = await client.exchangeCode('the-code', 'the-verifier');
    const body = new URLSearchParams(String(calls.at(-1)?.init?.body));

    expect(tokens).toEqual({ accessToken: 'access-1', refreshToken: 'refresh-1', expiresAt: 1_000_000 + 900_000 });
    expect(Object.fromEntries(body)).toEqual({
      grant_type: 'authorization_code',
      client_id: 'example-mobile',
      redirect_uri: 'exampleapp://oauth/callback',
      code: 'the-code',
      code_verifier: 'the-verifier',
    });
  });

  test('refresh envoie le refresh token', async () => {
    const { client, calls } = clientWith(() => json(tokenBody));

    await client.refresh('old-refresh');

    expect(Object.fromEntries(new URLSearchParams(String(calls.at(-1)?.init?.body)))).toEqual({
      grant_type: 'refresh_token',
      client_id: 'example-mobile',
      refresh_token: 'old-refresh',
    });
  });

  test('un refresh refusé (invalid_grant) est distinct d\'une panne', async () => {
    const { client } = clientWith(() => json({ error: 'invalid_grant', error_description: 'Révoqué.' }, 400));

    await expect(client.refresh('r')).rejects.toMatchObject({ code: 'invalid_grant', status: 400 });
  });

  test('une coupure réseau est une network_error', async () => {
    const fetchMock = (async (input: RequestInfo | URL) => {
      if (String(input).endsWith('/.well-known/oauth-authorization-server')) return json(metadata);
      throw new TypeError('Network request failed');
    }) as typeof fetch;
    const client = createIdentityClient({ ...config, fetch: fetchMock });

    await expect(client.refresh('r')).rejects.toMatchObject({ code: 'network_error' });
  });

  test('un 5xx et une limite de débit sont des server_error', async () => {
    for (const status of [500, 503, 429]) {
      const { client } = clientWith(() => json({ error: 'temporarily_unavailable' }, status));

      await expect(client.refresh('r')).rejects.toMatchObject({ code: 'server_error', status });
    }
  });

  test('une réponse sans refresh token est refusée', async () => {
    const { client } = clientWith(() => json({ access_token: 'a' }));

    await expect(client.refresh('r')).rejects.toBeInstanceOf(IdentityError);
  });
});

describe('délai d\'attente', () => {
  // Un fetch qui ne répond jamais, comme sur iOS vers une adresse injoignable : il n'échoue que si on l'abandonne.
  const hangingFetch = ((_input: RequestInfo | URL, init?: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    })) as typeof fetch;

  test('une réponse qui n\'arrive pas est une network_error, pour le refresh comme pour la révocation', async () => {
    vi.useFakeTimers();

    try {
      const client = createIdentityClient({ ...config, fetch: hangingFetch, timeoutMs: 5_000 });

      const refresh = expect(client.refresh('r')).rejects.toMatchObject({ code: 'network_error' });
      await vi.advanceTimersByTimeAsync(5_000);
      await refresh;

      const revoke = expect(client.revoke('r')).rejects.toMatchObject({ code: 'network_error' });
      await vi.advanceTimersByTimeAsync(5_000);
      await revoke;
    } finally {
      vi.useRealTimers();
    }
  });

  test('la connexion abandonnée n\'empêche pas de réessayer : les métadonnées ne restent pas en échec', async () => {
    vi.useFakeTimers();

    try {
      let hang = true;
      const flaky = ((input: RequestInfo | URL, init?: RequestInit) =>
        hang ? hangingFetch(input, init) : Promise.resolve(json(metadata))) as typeof fetch;
      const client = createIdentityClient({ ...config, fetch: flaky, timeoutMs: 5_000 });

      const first = expect(client.authorizeUrl({ state: 's', codeChallenge: 'c' })).rejects.toMatchObject({ code: 'network_error' });
      await vi.advanceTimersByTimeAsync(5_000);
      await first;

      hang = false;
      await expect(client.authorizeUrl({ state: 's', codeChallenge: 'c' })).resolves.toContain('/oauth/authorize');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('revoke', () => {
  test('envoie le token à l\'endpoint de révocation', async () => {
    const handler = vi.fn<Handler>(() => json({}));
    const { client, calls } = clientWith(handler);

    await client.revoke('refresh-1');

    expect(calls.at(-1)?.url).toBe(`${issuer}/oauth/revoke`);
    expect(Object.fromEntries(new URLSearchParams(String(calls.at(-1)?.init?.body)))).toEqual({
      client_id: 'example-mobile',
      token: 'refresh-1',
    });
  });
});

import { createHash } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import { createIdentityClient, IdentityError, type IdentityTokens } from './client';
import type { CryptoProvider } from './crypto';
import { createCookieTokenStore, createSharedRefresher, createWebSession, safeReturnTo, type CookieJar, type CookieOptions } from './web';

const issuer = 'http://identity.test';
const redirectUri = 'http://localhost:3000/auth/callback';

const crypto: CryptoProvider = {
  randomBytes: async (length) => Uint8Array.from({ length }, (_, index) => (index * 7 + 3) % 256),
  sha256Base64: async (value) => createHash('sha256').update(value).digest('base64'),
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function memoryJar(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  const options = new Map<string, CookieOptions>();
  const jar: CookieJar = {
    get: (name) => values.get(name),
    set: (name, value, cookieOptions) => {
      values.set(name, value);
      options.set(name, cookieOptions);
    },
    delete: (name) => {
      values.delete(name);
    },
  };

  return { jar, values, options };
}

function setup(cookies: Record<string, string> = {}, tokenResponse: () => Response | Promise<Response> = () => json({ access_token: 'access-new', refresh_token: 'refresh-new', expires_in: 900 })) {
  const requests: { url: string; body: URLSearchParams }[] = [];
  const fetchMock = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, body: new URLSearchParams(String(init?.body ?? '')) });

    if (url.endsWith('/.well-known/oauth-authorization-server')) {
      return json({
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
      });
    }

    if (url.endsWith('/oauth/revoke')) return json({});

    return tokenResponse();
  }) as typeof fetch;

  const client = createIdentityClient({
    issuer,
    clientId: 'autoreflex-map-web',
    clientSecret: 'web-secret',
    redirectUri,
    scope: 'profile email map:access',
    fetch: fetchMock,
    now: () => 1_000_000,
  });
  const cookieJar = memoryJar(cookies);
  const session = createWebSession({ client, jar: cookieJar.jar, crypto, secure: true, now: () => 1_000_000 });

  return { session, requests, ...cookieJar };
}

describe('client confidentiel', () => {
  test('envoie le secret à l\'échange du code, au refresh et à la révocation', async () => {
    const { session, requests, values } = setup();

    const url = new URL(await session.beginSignIn({ returnTo: '/dashboard' }));
    await session.finishSignIn(`${redirectUri}?code=the-code&state=${url.searchParams.get('state')}`);
    await session.tokenManager.getAccessToken({ rejected: 'access-new' });
    await session.signOut();

    const posts = requests.filter((request) => request.url.includes('/oauth/'));
    expect(posts.map((request) => request.body.get('client_secret'))).toEqual(['web-secret', 'web-secret', 'web-secret']);
    expect(posts.map((request) => request.body.get('grant_type'))).toEqual(['authorization_code', 'refresh_token', null]);
    expect(values.has('identity_access')).toBe(false);
  });

  test('l\'autorisation ne porte jamais le secret (il passe par le navigateur)', async () => {
    const { session } = setup();

    expect(await session.beginSignIn()).not.toContain('web-secret');
  });
});

describe('connexion', () => {
  test('mémorise PKCE et l\'adresse de retour dans un cookie court httpOnly, puis pose les trois cookies de session', async () => {
    const { session, values, options, requests } = setup();

    const url = new URL(await session.beginSignIn({ returnTo: '/dashboard/fiche' }));
    expect(options.get('identity_pkce')).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax', maxAge: 600 });
    expect(url.searchParams.get('prompt')).toBeNull();

    const result = await session.finishSignIn(`${redirectUri}?code=the-code&state=${url.searchParams.get('state')}`);

    expect(result).toEqual({ returnTo: '/dashboard/fiche' });
    expect(requests.at(-1)?.body.get('code')).toBe('the-code');
    expect(requests.at(-1)?.body.get('code_verifier')).toHaveLength(86);
    expect(Object.fromEntries(['access', 'refresh', 'expires'].map((key) => [key, values.get(`identity_${key}`)]))).toEqual({
      access: 'access-new',
      refresh: 'refresh-new',
      expires: String(1_000_000 + 900_000),
    });
    expect(options.get('identity_access')).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 30 * 86_400 });
    expect(values.has('identity_pkce')).toBe(false);
  });

  test('refuse un retour sans connexion en cours, ou dont le state est différent', async () => {
    const empty = setup();
    await expect(empty.session.finishSignIn(`${redirectUri}?code=c&state=x`)).rejects.toMatchObject({ code: 'invalid_state' });

    const { session, values } = setup();
    await session.beginSignIn();
    await expect(session.finishSignIn(`${redirectUri}?code=c&state=autre`)).rejects.toBeInstanceOf(IdentityError);
    expect(values.has('identity_pkce')).toBe(false);
    expect(values.has('identity_access')).toBe(false);
  });

  test('ne renvoie jamais vers un autre site', () => {
    expect(safeReturnTo('/dashboard?x=1')).toBe('/dashboard?x=1');
    expect(safeReturnTo('https://evil.test')).toBe('/');
    expect(safeReturnTo('//evil.test')).toBe('/');
    expect(safeReturnTo('/\\evil.test')).toBe('/');
    expect(safeReturnTo(null, '/dashboard')).toBe('/dashboard');
  });

  test('une déconnexion volontaire fait redemander les identifiants à la connexion suivante', async () => {
    const { session, values } = setup({ identity_access: 'a', identity_refresh: 'r', identity_expires: '9999999' });

    await session.signOut();
    expect(values.get('identity_relogin')).toBe('1');
    expect(new URL(await session.beginSignIn()).searchParams.get('prompt')).toBe('login');

    const state = new URL(await session.beginSignIn()).searchParams.get('state');
    await session.finishSignIn(`${redirectUri}?code=c&state=${state}`);
    expect(values.has('identity_relogin')).toBe(false);
  });
});

describe('session', () => {
  const expired = { identity_access: 'access-old', identity_refresh: 'refresh-old', identity_expires: String(1_000_000 - 1) };

  test('renouvelle un token expiré et réécrit les cookies (rotation)', async () => {
    const { session, values } = setup(expired);

    expect(await session.getAccessToken()).toBe('access-new');
    expect(values.get('identity_refresh')).toBe('refresh-new');
  });

  test('sans cookies, il n\'y a pas de session', async () => {
    const { session } = setup();

    expect(await session.hasSession()).toBe(false);
    await expect(session.getAccessToken()).rejects.toMatchObject({ name: 'NoSessionError' });
  });

  test('un refresh refusé efface la session ; une coupure réseau la garde', async () => {
    const refused = setup(expired, () => json({ error: 'invalid_grant' }, 400));
    await expect(refused.session.getAccessToken()).rejects.toMatchObject({ code: 'invalid_grant' });
    expect(refused.values.has('identity_refresh')).toBe(false);

    const down = setup(expired, () => json({}, 503));
    await expect(down.session.getAccessToken()).rejects.toMatchObject({ code: 'server_error' });
    expect(down.values.get('identity_refresh')).toBe('refresh-old');
  });

  test('deux requêtes simultanées avec le même refresh token ne font qu\'un refresh, dans deux sessions distinctes', async () => {
    let calls = 0;
    let open!: () => void;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    const refresh = async () => {
      calls++;
      await gate;

      return json({ access_token: 'access-new', refresh_token: 'refresh-new', expires_in: 900 });
    };
    const requests: string[] = [];
    const fetchMock = (async (input: RequestInfo | URL) => {
      const url = String(input);
      requests.push(url);

      if (url.endsWith('/.well-known/oauth-authorization-server')) {
        return json({ issuer, authorization_endpoint: `${issuer}/a`, token_endpoint: `${issuer}/oauth/token`, revocation_endpoint: `${issuer}/r` });
      }

      return refresh();
    }) as typeof fetch;
    const client = createIdentityClient({ issuer, clientId: 'c', redirectUri, scope: 's', fetch: fetchMock, now: () => 1_000_000 });
    const shared = createSharedRefresher(client);
    const first = memoryJar(expired);
    const second = memoryJar(expired);
    const one = createWebSession({ client, jar: first.jar, crypto, secure: true, refresher: shared, now: () => 1_000_000 });
    const two = createWebSession({ client, jar: second.jar, crypto, secure: true, refresher: shared, now: () => 1_000_000 });

    const pending = Promise.all([one.getAccessToken(), two.getAccessToken()]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    open();

    expect(await pending).toEqual(['access-new', 'access-new']);
    expect(calls).toBe(1);
    expect([first.values.get('identity_refresh'), second.values.get('identity_refresh')]).toEqual(['refresh-new', 'refresh-new']);
  });
});

describe('createSharedRefresher', () => {
  test('ne retient pas un échec : le suivant réessaie', async () => {
    let calls = 0;
    const tokens: IdentityTokens = { accessToken: 'a', refreshToken: 'r', expiresAt: 1 };
    const shared = createSharedRefresher({
      refresh: async () => {
        calls++;
        if (calls === 1) throw new IdentityError('coupure', 'network_error');

        return tokens;
      },
    });

    await expect(shared.refresh('old')).rejects.toBeInstanceOf(IdentityError);
    await expect(shared.refresh('old')).resolves.toBe(tokens);
    expect(calls).toBe(2);
  });
});

describe('createCookieTokenStore', () => {
  test('ne lit une session que si les trois cookies sont là', async () => {
    const { jar } = memoryJar({ identity_access: 'a', identity_refresh: 'r' });

    expect(await createCookieTokenStore(jar, { secure: false }).read()).toBeNull();
  });
});

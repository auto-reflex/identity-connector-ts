import { createHash } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import { createIdentityClient, IdentityError, parseQuery } from './client';
import type { CryptoProvider } from './crypto';
import { createIdentitySession, type AuthSessionResult } from './session';
import { createTokenManager, type TokenStore } from './token-manager';
import type { IdentityTokens } from './client';

const issuer = 'http://identity.test';
const redirectUri = 'exampleapp://oauth/callback';

const crypto: CryptoProvider = {
  randomBytes: async (length) => Uint8Array.from({ length }, (_, index) => (index * 7 + 3) % 256),
  sha256Base64: async (value) => createHash('sha256').update(value).digest('base64'),
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function setup(openAuthSession: (url: string, redirect: string) => Promise<AuthSessionResult>, initial: IdentityTokens | null = null) {
  const requests: { url: string; body: string }[] = [];
  let revoked: Promise<Response> | null = null;
  let revokeHandler: () => Promise<Response> = async () => json({});

  const fetchMock = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, body: String(init?.body ?? '') });

    if (url.endsWith('/.well-known/oauth-authorization-server')) {
      return json({
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
      });
    }

    if (url.endsWith('/oauth/revoke')) {
      revoked = revokeHandler();

      return revoked;
    }

    return json({ access_token: 'access-new', refresh_token: 'refresh-new', expires_in: 900 });
  }) as typeof fetch;

  let stored = initial;
  const store: TokenStore = {
    read: async () => stored,
    write: async (tokens) => {
      stored = tokens;
    },
    clear: async () => {
      stored = null;
    },
  };
  let forceLogin = false;
  const client = createIdentityClient({
    issuer,
    clientId: 'example-mobile',
    redirectUri,
    scope: 'profile email example:access',
    fetch: fetchMock,
    now: () => 1_000_000,
  });
  const tokenManager = createTokenManager({ store, client, now: () => 1_000_000 });
  const session = createIdentitySession({
    client,
    tokenManager,
    crypto,
    openAuthSession,
    flags: {
      readForceLogin: async () => forceLogin,
      writeForceLogin: async (force) => {
        forceLogin = force;
      },
    },
  });

  return {
    session,
    requests,
    stored: () => stored,
    forceLogin: () => forceLogin,
    setForceLogin: (value: boolean) => {
      forceLogin = value;
    },
    onRevoke: (handler: () => Promise<Response>) => {
      revokeHandler = handler;
    },
    revoked: () => revoked,
  };
}

const existing: IdentityTokens = { accessToken: 'access-old', refreshToken: 'refresh-old', expiresAt: 2_000_000 };

describe('signIn', () => {
  test('ouvre la page avec PKCE, échange le code et stocke les tokens', async () => {
    let opened: { url: string; redirect: string } | null = null;
    const env = setup(async (url, redirect) => {
      opened = { url, redirect };
      const state = parseQuery(url).state;

      return { type: 'success', url: `${redirectUri}?code=the-code&state=${state}` };
    });

    expect(await env.session.signIn()).toBe('signed-in');

    expect(opened!.redirect).toBe(redirectUri);
    expect(parseQuery(opened!.url)).toMatchObject({ client_id: 'example-mobile', code_challenge_method: 'S256' });
    expect(env.stored()).toEqual({ accessToken: 'access-new', refreshToken: 'refresh-new', expiresAt: 1_000_000 + 900_000 });
    expect(await env.session.hasSession()).toBe(true);

    const exchange = env.requests.find((request) => request.url.endsWith('/oauth/token'))!;
    expect(new URLSearchParams(exchange.body).get('code')).toBe('the-code');
    expect(new URLSearchParams(exchange.body).get('code_verifier')).toHaveLength(86);
  });

  test('après une déconnexion, redemande les identifiants une seule fois', async () => {
    const urls: string[] = [];
    const env = setup(async (url) => {
      urls.push(url);

      return { type: 'success', url: `${redirectUri}?code=c&state=${parseQuery(url).state}` };
    });
    env.setForceLogin(true);

    await env.session.signIn();
    await env.session.signIn();

    expect(parseQuery(urls[0]).prompt).toBe('login');
    expect(parseQuery(urls[1]).prompt).toBeUndefined();
    expect(env.forceLogin()).toBe(false);
  });

  test('fermer le navigateur est un abandon, pas une erreur', async () => {
    const env = setup(async () => ({ type: 'cancel' }));

    expect(await env.session.signIn()).toBe('cancelled');
    expect(env.stored()).toBeNull();
  });

  test("refuser l'accès est un abandon", async () => {
    const env = setup(async (url) => ({
      type: 'success',
      url: `${redirectUri}?error=access_denied&state=${parseQuery(url).state}`,
    }));

    expect(await env.session.signIn()).toBe('cancelled');
  });

  test('un state différent est refusé et rien n\'est stocké', async () => {
    const env = setup(async () => ({ type: 'success', url: `${redirectUri}?code=c&state=forged` }));

    await expect(env.session.signIn()).rejects.toMatchObject({ code: 'invalid_state' } satisfies Partial<IdentityError>);
    expect(env.stored()).toBeNull();
  });
});

describe('signOut', () => {
  test('efface les jetons tout de suite et révoque en arrière-plan, sans attendre Identity', async () => {
    const env = setup(async () => ({ type: 'cancel' }), existing);
    env.onRevoke(() => new Promise<Response>(() => undefined)); // Identity ne répond jamais

    await env.session.signOut();

    expect(env.stored()).toBeNull();
    expect(env.forceLogin()).toBe(true);
    expect(await env.session.hasSession()).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(env.requests.some((request) => request.url.endsWith('/oauth/revoke'))).toBe(true);
  });

  test('une révocation en échec ne fait pas échouer la déconnexion', async () => {
    const env = setup(async () => ({ type: 'cancel' }), existing);
    env.onRevoke(async () => {
      throw new Error('réseau coupé');
    });

    await expect(env.session.signOut()).resolves.toBeUndefined();
    expect(env.stored()).toBeNull();
  });

  test('sans session, ne révoque rien', async () => {
    const env = setup(async () => ({ type: 'cancel' }));

    await env.session.signOut();

    expect(env.requests.some((request) => request.url.endsWith('/oauth/revoke'))).toBe(false);
    expect(env.forceLogin()).toBe(true);
  });
});

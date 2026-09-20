import { describe, expect, test } from 'vitest';

import { IdentityError, type IdentityTokens } from './client';
import { createTokenManager, NoSessionError, type TokenStore } from './token-manager';

function memoryStore(initial: IdentityTokens | null = null) {
  let tokens = initial;
  const writes: IdentityTokens[] = [];
  const store: TokenStore = {
    read: async () => tokens,
    write: async (value) => {
      writes.push(value);
      tokens = value;
    },
    clear: async () => {
      tokens = null;
    },
  };

  return { store, writes, stored: () => tokens };
}

const now = 1_000_000;
const valid: IdentityTokens = { accessToken: 'access-1', refreshToken: 'refresh-1', expiresAt: now + 600_000 };
const expired: IdentityTokens = { accessToken: 'access-old', refreshToken: 'refresh-old', expiresAt: now - 1_000 };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

describe('getAccessToken', () => {
  test('sans session : NoSessionError', async () => {
    const manager = createTokenManager({ store: memoryStore().store, client: { refresh: async () => valid }, now: () => now });

    await expect(manager.getAccessToken()).rejects.toBeInstanceOf(NoSessionError);
  });

  test('rend le token tant qu\'il n\'expire pas dans la marge, sans refresh', async () => {
    let refreshes = 0;
    const manager = createTokenManager({
      store: memoryStore(valid).store,
      client: { refresh: async () => { refreshes++; return valid; } },
      now: () => now,
    });

    await expect(manager.getAccessToken()).resolves.toBe('access-1');
    expect(refreshes).toBe(0);
  });

  test('renouvelle un token qui expire dans la marge de 60 s', async () => {
    const soon: IdentityTokens = { ...valid, expiresAt: now + 30_000 };
    const fresh: IdentityTokens = { accessToken: 'access-2', refreshToken: 'refresh-2', expiresAt: now + 900_000 };
    const { store, stored } = memoryStore(soon);
    const manager = createTokenManager({ store, client: { refresh: async () => fresh }, now: () => now });

    await expect(manager.getAccessToken()).resolves.toBe('access-2');
    expect(stored()).toEqual(fresh);
  });

  test('cinq appels simultanés avec un token expiré ne font qu\'un seul refresh', async () => {
    const gate = deferred<IdentityTokens>();
    let refreshes = 0;
    const manager = createTokenManager({
      store: memoryStore(expired).store,
      client: { refresh: () => { refreshes++; return gate.promise; } },
      now: () => now,
    });

    const calls = Array.from({ length: 5 }, () => manager.getAccessToken());
    gate.resolve({ accessToken: 'access-2', refreshToken: 'refresh-2', expiresAt: now + 900_000 });

    await expect(Promise.all(calls)).resolves.toEqual(Array(5).fill('access-2'));
    expect(refreshes).toBe(1);
  });

  test('écrit le nouveau refresh token avant de rendre le token (la rotation a déjà révoqué l\'ancien)', async () => {
    const fresh: IdentityTokens = { accessToken: 'access-2', refreshToken: 'refresh-2', expiresAt: now + 900_000 };
    const { store, writes } = memoryStore(expired);
    const manager = createTokenManager({ store, client: { refresh: async () => fresh }, now: () => now });

    await manager.getAccessToken();

    expect(writes).toEqual([fresh]);
  });

  test('un 401 rejoué : le token refusé est remplacé par un refresh, une seule fois pour tous', async () => {
    let refreshes = 0;
    const fresh: IdentityTokens = { accessToken: 'access-2', refreshToken: 'refresh-2', expiresAt: now + 900_000 };
    const manager = createTokenManager({
      store: memoryStore(valid).store,
      client: { refresh: async () => { refreshes++; return fresh; } },
      now: () => now,
    });

    const [a, b] = await Promise.all([
      manager.getAccessToken({ rejected: 'access-1' }),
      manager.getAccessToken({ rejected: 'access-1' }),
    ]);
    // Un appel tardif dont le token refusé a déjà été remplacé reçoit le nouveau sans refaire de refresh.
    const late = await manager.getAccessToken({ rejected: 'access-1' });

    expect([a, b, late]).toEqual(['access-2', 'access-2', 'access-2']);
    expect(refreshes).toBe(1);
  });
});

describe('perte et conservation de la session', () => {
  test('invalid_grant efface les jetons et prévient', async () => {
    const { store, stored } = memoryStore(expired);
    const manager = createTokenManager({
      store,
      client: { refresh: async () => { throw new IdentityError('Révoqué.', 'invalid_grant', 400); } },
      now: () => now,
    });
    let lost = 0;
    manager.onSessionLost(() => { lost++; });

    await expect(manager.getAccessToken()).rejects.toMatchObject({ code: 'invalid_grant' });

    expect(stored()).toBeNull();
    expect(lost).toBe(1);
    await expect(manager.getAccessToken()).rejects.toBeInstanceOf(NoSessionError);
  });

  test('une panne réseau garde les jetons et ne prévient pas', async () => {
    const { store, stored } = memoryStore(expired);
    const manager = createTokenManager({
      store,
      client: { refresh: async () => { throw new IdentityError('Hors ligne.', 'network_error'); } },
      now: () => now,
    });
    let lost = 0;
    manager.onSessionLost(() => { lost++; });

    await expect(manager.getAccessToken()).rejects.toMatchObject({ code: 'network_error' });

    expect(stored()).toEqual(expired);
    expect(lost).toBe(0);
  });

  test('après un échec, le refresh suivant repart (rien de collé)', async () => {
    let attempt = 0;
    const fresh: IdentityTokens = { accessToken: 'access-2', refreshToken: 'refresh-2', expiresAt: now + 900_000 };
    const manager = createTokenManager({
      store: memoryStore(expired).store,
      client: {
        refresh: async () => {
          attempt++;
          if (attempt === 1) throw new IdentityError('Hors ligne.', 'network_error');

          return fresh;
        },
      },
      now: () => now,
    });

    await expect(manager.getAccessToken()).rejects.toMatchObject({ code: 'network_error' });
    await expect(manager.getAccessToken()).resolves.toBe('access-2');
  });

  test('set remplace la session et clear la retire sans prévenir', async () => {
    const { store, stored } = memoryStore(expired);
    const manager = createTokenManager({ store, client: { refresh: async () => valid }, now: () => now });
    let lost = 0;
    manager.onSessionLost(() => { lost++; });

    await manager.set(valid);
    expect(await manager.current()).toEqual(valid);
    expect(stored()).toEqual(valid);

    await manager.clear();
    expect(await manager.current()).toBeNull();
    expect(lost).toBe(0);
  });
});

import { IdentityError, type IdentityClient } from './client';
import type { CryptoProvider } from './crypto';
import { createPkceRequest } from './pkce';
import type { TokenManager } from './token-manager';

/** Résultat d'`openAuthSession` : `success` avec l'URL de retour, tout autre type (fermeture, annulation) = abandon. */
export type AuthSessionResult = { type: 'success'; url: string } | { type: string; url?: undefined };

export type SessionFlags = {
  /** Après une déconnexion volontaire, la prochaine connexion redemande les identifiants (changement de compte). */
  readForceLogin: () => Promise<boolean>;
  writeForceLogin: (force: boolean) => Promise<void>;
};

export type IdentitySessionOptions = {
  client: IdentityClient;
  tokenManager: TokenManager;
  crypto: CryptoProvider;
  flags: SessionFlags;
  /**
   * Ouvre l'adresse d'autorisation dans le navigateur du système et rend l'URL de retour
   * (`WebBrowser.openAuthSessionAsync` sur Expo).
   */
  openAuthSession: (url: string, redirectUri: string) => Promise<AuthSessionResult>;
};

export type SignInResult = 'signed-in' | 'cancelled';

/** Le parcours de connexion et de déconnexion, commun aux applications ; la plateforme est injectée. */
export function createIdentitySession({ client, tokenManager, crypto, flags, openAuthSession }: IdentitySessionOptions) {
  return {
    /** Une session est ouverte : des jetons sont en mémoire ou stockés (sans préjuger de leur validité). */
    async hasSession(): Promise<boolean> {
      return (await tokenManager.current()) !== null;
    },

    /**
     * Ouvre la page d'AutoGteck (connexion, ou création du compte, puis consentement), puis échange le code contre les
     * tokens. Fermer le navigateur ou refuser l'accès n'est pas une erreur : `cancelled`.
     */
    async signIn(): Promise<SignInResult> {
      const pkce = await createPkceRequest(crypto);
      const url = await client.authorizeUrl({
        state: pkce.state,
        codeChallenge: pkce.challenge,
        forceLogin: await flags.readForceLogin(),
      });

      const result = await openAuthSession(url, client.redirectUri);

      if (result.type !== 'success' || result.url === undefined) return 'cancelled';

      let code: string;

      try {
        code = client.parseCallback(result.url, pkce.state);
      } catch (error) {
        if (error instanceof IdentityError && error.code === 'access_denied') return 'cancelled';
        throw error;
      }

      await tokenManager.set(await client.exchangeCode(code, pkce.verifier));
      await flags.writeForceLogin(false);

      return 'signed-in';
    },

    /**
     * Efface les jetons tout de suite, puis révoque le refresh token à Identity en arrière-plan (Identity injoignable :
     * la déconnexion locale a eu lieu quand même, sans attendre). La prochaine connexion redemandera les identifiants.
     */
    async signOut(): Promise<void> {
      const tokens = await tokenManager.current();

      await tokenManager.clear();
      await flags.writeForceLogin(true);

      if (!tokens) return;

      // L'appareil n'a plus rien ; le token restera valable côté Identity jusqu'à son expiration au pire.
      void client.revoke(tokens.refreshToken).catch(() => undefined);
    },
  };
}

export type IdentitySession = ReturnType<typeof createIdentitySession>;

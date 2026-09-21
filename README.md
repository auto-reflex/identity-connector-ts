# @autogteck/identity-connector (TypeScript)

Client OAuth2 d'AutoGteck Identity pour les applications TypeScript : mobile Expo, et à terme le
back-office Next.js. Le pendant PHP est [`identity-connector-php`](https://github.com/auto-reflex/identity-connector-php),
qui vérifie les tokens côté API.

- **Authorization Code + PKCE (S256)**, client public, dans le navigateur du système. L'application ne voit jamais le
  mot de passe.
- **Refresh token à rotation, usage unique** : un seul refresh à la fois (`getAccessToken`), écrit avant toute autre
  chose ; seul un refus d'Identity (`invalid_grant`) ferme la session, une coupure réseau la garde.
- **Aucune dépendance de plateforme** : uniquement `fetch`. Le hasard, le SHA-256, le stockage des jetons et
  l'ouverture du navigateur sont **injectés** par l'application.
- Identity n'expose pas OIDC (pas d'`id_token`, pas de fin de session) : `expo-auth-session` et `oidc-client-ts` ne
  conviennent pas, d'où ce client à la main (RFC 6749, 7636, 8414).

Le guide d'intégration complet (API, mobile, vérification) est dans la documentation interne AutoGteck (`docs/connecteur/`).

## Installation

```bash
npm install github:auto-reflex/identity-connector-ts#v0.1.0
```

Le dépôt est public et **le paquet est livré en TypeScript** (`main: src/index.ts`), comme les modules Expo : Metro le
compile. Avec Jest (`jest-expo`), il faut l'ajouter aux paquets transformés. Un `transformIgnorePatterns` déclaré dans
`package.json` **remplace** celui du preset : reprendre ses trois entrées (valeurs de `jest-expo` 57) et ajouter
`@autogteck` :

```json
"jest": {
  "preset": "jest-expo",
  "transformIgnorePatterns": [
    "/node_modules/(?!(.pnpm|react-native|@react-native|@react-native-community|expo|@expo|@expo-google-fonts|react-navigation|@react-navigation|@sentry/react-native|native-base|standard-navigation|@autogteck))",
    "/node_modules/react-native-reanimated/plugin/",
    "/node_modules/@react-native/babel-preset/"
  ]
}
```

## Utilisation (Expo)

Ce que chaque produit garde chez lui : la configuration (client, schéma, scopes) et le stockage des jetons.

```ts
// src/core/identity/index.ts
import * as Crypto from 'expo-crypto';
import * as WebBrowser from 'expo-web-browser';
import {
  createIdentityClient,
  createIdentitySession,
  createTokenManager,
  type CryptoProvider,
} from '@autogteck/identity-connector';

import { identityConfig } from './config';
import { createSecureTokenStore, readForceLogin, writeForceLogin } from './token-store';

WebBrowser.maybeCompleteAuthSession(); // web : termine la session d'autorisation ouverte dans une fenêtre

const crypto: CryptoProvider = {
  randomBytes: (length) => Crypto.getRandomBytesAsync(length),
  sha256Base64: (value) =>
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, value, { encoding: Crypto.CryptoEncoding.BASE64 }),
};

export const identityClient = createIdentityClient(identityConfig);
export const tokenManager = createTokenManager({ store: createSecureTokenStore(), client: identityClient });
export const getAccessToken = tokenManager.getAccessToken;

const session = createIdentitySession({
  client: identityClient,
  tokenManager,
  crypto,
  flags: { readForceLogin, writeForceLogin },
  openAuthSession: (url, redirectUri) => WebBrowser.openAuthSessionAsync(url, redirectUri),
});

export const { hasSession, signIn: signInWithAutoGteck, signOut: signOutFromIdentity } = session;
```

`identityConfig` : `{ issuer, clientId, redirectUri, scope, uiLocales? }`. `issuer` est **identique** au claim `iss` des
tokens, à `IDENTITY_ISSUER` de l'API et à l'adresse publique d'Identity.

`TokenStore` (`read`, `write`, `clear`) est à fournir : sur Expo, le trousseau (`expo-secure-store`) en **trois clés**
(accès, refresh, échéance), car un JWT RS256 et un refresh approchent la limite de 2048 octets d'une valeur iOS.

## Utilisation (navigateur, Node, Next.js)

`webCrypto` est le fournisseur fondé sur Web Crypto (navigateurs, Node 20+).

### Application web côté serveur : client confidentiel (Next.js)

Un site comme la Map est un client **confidentiel** : `clientSecret` (côté serveur seulement, jamais `NEXT_PUBLIC_*`)
accompagne l'échange du code, le refresh et la révocation, et les tokens vivent dans des **cookies httpOnly**, jamais dans
le navigateur. `createWebSession` porte tout le parcours ; le paquet ne connaît aucun framework, l'application fournit un
`CookieJar` (`get`, `set`, `delete`) :

```ts
import { createIdentityClient, createSharedRefresher, createWebSession, webCrypto } from '@autogteck/identity-connector';

const client = createIdentityClient({ issuer, clientId: 'autoreflex-map-web', clientSecret, redirectUri, scope: 'profile email map:access' });
const refresher = createSharedRefresher(client); // une fois par processus : voir plus bas

export function webSession(jar: CookieJar) {
  return createWebSession({ client, jar, crypto: webCrypto, secure: process.env.NODE_ENV === 'production', refresher });
}

// /login (route handler)        : redirect(await webSession(await cookieJar()).beginSignIn({ returnTo }))
// /auth/callback (route handler): const { returnTo } = await webSession(jar).finishSignIn(request.url); redirect(returnTo)
// appel d'API (serveur)         : const token = await webSession(jar).getAccessToken({ rejected })
// /logout                       : await webSession(jar).signOut()
```

- **Trois cookies** (`identity_access`, `identity_refresh`, `identity_expires`, préfixe configurable) : un JWT RS256 et un refresh
  token ne tiennent pas ensemble dans les 4 Ko d'un cookie. Le cookie court `identity_pkce` (10 min) porte PKCE et l'adresse de retour ; `safeReturnTo`
  n'accepte qu'une adresse interne. `identity_relogin` fait redemander les identifiants après une déconnexion volontaire.
- **Un refresh à usage unique** : une page déclenche plusieurs requêtes en parallèle avec le même refresh token périmé. `createSharedRefresher`
  les partage pendant 30 s dans le processus (elles reçoivent les mêmes nouveaux tokens) ; sans lui, la seconde recevrait
  `invalid_grant` et la personne serait déconnectée à tort. Seul `invalid_grant` efface la session ; une coupure réseau la garde.
- **Où renouveler** : les composants serveur ne peuvent pas écrire de cookies. Le renouvellement a lieu dans `proxy.ts`, avec un
  `CookieJar` construit sur la requête et la réponse, avant que la page ne lise le token.
- Un 401 de l'API : `getAccessToken({ rejected: token })` force un refresh (ou rend le token qu'un autre appel a déjà renouvelé) ; rejouer une fois, puis effacer la session.

## API

| Export | Rôle |
| --- | --- |
| `createIdentityClient(config)` | Métadonnées RFC 8414 (émetteur vérifié), `clientSecret` optionnel (client confidentiel), `authorizeUrl`, `parseCallback` (vérifie `state`), `exchangeCode`, `refresh`, `revoke`. Délai d'attente de 15 s par appel. |
| `createTokenManager({ store, client })` | `getAccessToken({ rejected? })` (refresh anticipé de 60 s, un seul vol), `current`, `set`, `clear`, `onSessionLost`. |
| `createWebSession({ client, jar, crypto, secure })` | Application web serveur (client confidentiel) : `beginSignIn`, `finishSignIn`, `getAccessToken`, `hasSession`, `signOut`, sur des cookies httpOnly. `createCookieTokenStore`, `createSharedRefresher`, `safeReturnTo`. |
| `createIdentitySession(...)` | `signIn()` → `'signed-in' \| 'cancelled'`, `signOut()` (efface tout de suite, révoque en arrière-plan), `hasSession()`. |
| `createPkceRequest(crypto)`, `webCrypto`, `CryptoProvider` | PKCE et accès à la plateforme. |
| `IdentityError` (`code`) | `invalid_grant` (session perdue), `network_error` et `server_error` (session gardée), `access_denied`, `invalid_state`, `invalid_response`, `rejected`. |
| `NoSessionError` | Aucun jeton. |

## Développement

```bash
npm install
npm run check      # tsc --noEmit + vitest
```

Les tests couvrent le vecteur PKCE de la RFC 7636, les métadonnées, l'échange et le refresh, le délai d'attente, cinq
appels simultanés = un seul refresh, la rotation écrite avant la réponse, et le parcours de connexion/déconnexion.

## Versions

Tags `vX.Y.Z`, installés par `github:…#vX.Y.Z`. Une correction ici se reporte dans les applications par un changement
de tag et `npm install`. Licence : voir `LICENSE`.

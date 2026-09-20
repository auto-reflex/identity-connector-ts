# @autoreflex/identity-connector (TypeScript)

Client OAuth2 d'AutoReflex Identity pour les applications TypeScript : mobile Expo, et à terme le
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

Le guide d'intégration complet (API, mobile, vérification) est dans la documentation interne AutoReflex (`docs/connecteur/`).

## Installation

```bash
npm install github:auto-reflex/identity-connector-ts#v0.1.0
```

Le dépôt est public et **le paquet est livré en TypeScript** (`main: src/index.ts`), comme les modules Expo : Metro le
compile. Avec Jest (`jest-expo`), il faut l'ajouter aux paquets transformés :

```json
"jest": {
  "preset": "jest-expo",
  "transformIgnorePatterns": [
    "node_modules/(?!((jest-)?react-native|@react-native(-community)?|expo(nent)?|@expo(nent)?/.*|@expo-google-fonts/.*|react-navigation|@react-navigation/.*|@sentry/react-native|native-base|react-native-svg|@autoreflex/.*))"
  ]
}
```

(reprendre la valeur par défaut de `jest-expo` et y ajouter `@autoreflex/.*`.)

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
} from '@autoreflex/identity-connector';

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

export const { hasSession, signIn: signInWithAutoReflex, signOut: signOutFromIdentity } = session;
```

`identityConfig` : `{ issuer, clientId, redirectUri, scope, uiLocales? }`. `issuer` est **identique** au claim `iss` des
tokens, à `IDENTITY_ISSUER` de l'API et à l'adresse publique d'Identity.

`TokenStore` (`read`, `write`, `clear`) est à fournir : sur Expo, le trousseau (`expo-secure-store`) en **trois clés**
(accès, refresh, échéance), car un JWT RS256 et un refresh approchent la limite de 2048 octets d'une valeur iOS.

## Utilisation (navigateur, Node, Next.js)

`webCrypto` est le fournisseur fondé sur Web Crypto (navigateurs, Node 20+). Le back-office d'AutoDonuts sera un client
**confidentiel** (secret côté serveur) : ce paquet en couvre le noyau (`createIdentityClient`, `createTokenManager`), pas
encore le secret client ni les cookies de session.

## API

| Export | Rôle |
| --- | --- |
| `createIdentityClient(config)` | Métadonnées RFC 8414 (émetteur vérifié), `authorizeUrl`, `parseCallback` (vérifie `state`), `exchangeCode`, `refresh`, `revoke`. Délai d'attente de 15 s par appel. |
| `createTokenManager({ store, client })` | `getAccessToken({ rejected? })` (refresh anticipé de 60 s, un seul vol), `current`, `set`, `clear`, `onSessionLost`. |
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

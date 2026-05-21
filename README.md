<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# authio/authio (PHP)

Authio PHP SDK. Verifies session JWTs against Authio's JWKS and kicks off
magic-link sign-in flows.

## Install

```bash
composer require authio/authio
```

## Quickstart

```php
use Authio\Authio;

$authio = new Authio([
    'api_key' => getenv('AUTHIO_SECRET_KEY'),
    'api_url' => 'https://api.authio.com',
    'publishable_key' => getenv('AUTHIO_PUBLISHABLE_KEY'),
]);

// In a controller / middleware:
$session = $authio->verifyToken($_COOKIE['authio_session'] ?? null);
if ($session === null) {
    header('Location: /auth/sign-in');
    exit;
}

// $session->userId  — always set
// $session->orgId   — string|null, null until the user picks an org
// $session->role    — string|null
// $session->claims  — custom T2.4 claims, merged
```

## Laravel integration

The `create-authio-app --framework=laravel` template wires a singleton via
`AppServiceProvider` and an `AuthenticateWithAuthio` middleware that uses
`$authio->verifyToken()` on the `authio_session` cookie.

## API

| Method                               | Description                                          |
| ------------------------------------ | ---------------------------------------------------- |
| `new Authio($options)`               | Construct with `api_key`, `api_url`, `publishable_key`. |
| `verifyToken(?string $token): ?Session` | Verify JWT against the cached JWKS. `null` on failure. |
| `signIn(string $email, string $redirectUrl): array` | POST to `/v1/auth/magic-link/start`. |

`Session` exposes `sessionId`, `userId`, `orgId`, `role`, `expiresAt`,
`claims`, `isImpersonation`, `impersonatorEmail`.

## Requirements

- PHP 8.2+
- `ext-openssl` for EdDSA verification
- `firebase/php-jwt` 6.x (installed automatically)

## License

MIT

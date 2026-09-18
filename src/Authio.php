<?php

declare(strict_types=1);

namespace Authio;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\RequestException;

/**
 * Authio PHP SDK entry point.
 *
 * Pair this with the `AuthenticateWithAuthio` middleware (Laravel) or
 * any equivalent request guard. `verifyToken()` checks an access JWT
 * against Authio's cached JWKS and returns a typed `Session` or null.
 */
final class Authio
{
    private string $apiKey;
    private string $apiUrl;
    private string $publishableKey;
    private string $issuer;
    private string $audience;
    private JwksVerifier $verifier;
    private HttpClient $http;

    /**
     * @param array{
     *   api_key?: string,
     *   api_url?: string,
     *   publishable_key?: string,
     *   issuer?: string,
     *   audience?: string,
     *   project_id?: string,
     *   http_client?: HttpClient
     * } $options
     */
    public function __construct(array $options = [])
    {
        $this->apiKey = (string) ($options['api_key'] ?? '');
        $this->apiUrl = rtrim((string) ($options['api_url'] ?? 'https://api.authio.com'), '/');
        $this->publishableKey = (string) ($options['publishable_key'] ?? '');
        $this->issuer = (string) ($options['issuer'] ?? $this->apiUrl);
        $this->audience = (string) ($options['audience'] ?? 'authio');
        $this->http = $options['http_client'] ?? new HttpClient(['timeout' => 30.0]);
        // Tenant binding, defaulting from the env var the docs already ask
        // for. Without it, a token minted in ANY Authio project verifies
        // here — see JwksVerifier::assertTenant.
        $projectId = (string) ($options['project_id'] ?? getenv('AUTHIO_PROJECT_ID') ?: '');
        $this->verifier = new JwksVerifier(
            $this->apiUrl,
            $this->issuer,
            $this->audience,
            $this->http,
            $projectId !== '' ? $projectId : null,
        );
    }

    /**
     * Verify an Authio access token. Returns the typed Session or null
     * when the token is missing, expired, or cryptographically invalid.
     */
    public function verifyToken(?string $token): ?Session
    {
        if ($token === null || $token === '') {
            return null;
        }
        try {
            $claims = $this->verifier->verify($token);
        } catch (\Throwable) {
            return null;
        }

        $reserved = [
            'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nbf', 'scope', 'scopes',
            'sid', 'act_org', 'act_role', 'client_id', 'token_type',
            'project_id', 'is_impersonation', 'impersonator_user_id',
            'impersonator_email', 'imp_grant_id',
        ];
        $merged = [];
        foreach ($claims as $k => $v) {
            if (!in_array($k, $reserved, true)) {
                $merged[$k] = $v;
            }
        }

        return new Session(
            sessionId: (string) ($claims['sid'] ?? ''),
            userId: (string) ($claims['sub'] ?? ''),
            orgId: !empty($claims['act_org']) ? (string) $claims['act_org'] : null,
            role: !empty($claims['act_role']) ? (string) $claims['act_role'] : null,
            expiresAt: isset($claims['exp'])
                ? gmdate('c', (int) $claims['exp'])
                : gmdate('c'),
            claims: $merged,
            isImpersonation: ($claims['is_impersonation'] ?? null) === true,
            impersonatorEmail: $claims['impersonator_email'] ?? null,
        );
    }

    /**
     * Browser sign-in helper. Kicks off the magic-link flow.
     * In Laravel templates this is invoked client-side from JS, but
     * server-side controllers can use it for test fixtures / API flows.
     *
     * @return array<string, mixed>
     */
    public function signIn(string $email, string $redirectUrl): array
    {
        try {
            $res = $this->http->post($this->apiUrl . '/v1/auth/magic-link/start', [
                'headers' => [
                    'content-type' => 'application/json',
                    'x-publishable-key' => $this->publishableKey,
                ],
                'json' => [
                    'email' => $email,
                    'redirect_url' => $redirectUrl,
                ],
            ]);
        } catch (RequestException $e) {
            throw new AuthioException(
                'authio.sign_in_failed',
                $e->getMessage(),
                $e->getCode() ?: 500,
                $e,
            );
        }
        /** @var array<string, mixed> $data */
        $data = json_decode((string) $res->getBody(), true) ?? [];

        return $data;
    }

    public function getApiUrl(): string
    {
        return $this->apiUrl;
    }

    public function getPublishableKey(): string
    {
        return $this->publishableKey;
    }
}

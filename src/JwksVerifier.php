<?php

declare(strict_types=1);

namespace Authio;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as HttpClient;

/**
 * Verifies Authio access tokens against the cached JWKS.
 *
 * Authio's auth-core signs JWTs with EdDSA (Ed25519). The cached JWKS
 * is fetched lazily and re-fetched once per `cacheTtl` seconds.
 */
final class JwksVerifier
{
    private const CACHE_TTL = 600; // 10 minutes
    private const COOLDOWN = 30;   // 30s minimum between forced refetches

    private static bool $warnedNoProject = false;

    /** @var array<string, \Firebase\JWT\Key>|null */
    private ?array $keys = null;
    private int $fetchedAt = 0;

    public function __construct(
        private readonly string $apiUrl,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly HttpClient $http,
        private readonly ?string $projectId = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function verify(string $token): array
    {
        $keys = $this->getKeys();
        $payload = JWT::decode($token, $keys);
        $arr = (array) $payload;
        // iss/aud are REQUIRED, not "checked when present". The previous
        // isset() guards meant a token that simply omitted the claim
        // skipped the check rather than failing it — a verifier should
        // never be weakened by a claim being absent.
        if (!isset($arr['iss']) || $arr['iss'] !== $this->issuer) {
            throw new \RuntimeException('authio: token issuer mismatch');
        }
        if (!isset($arr['aud'])) {
            throw new \RuntimeException('authio: token audience mismatch');
        }
        $aud = $arr['aud'];
        $audList = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->audience, $audList, true)) {
            throw new \RuntimeException('authio: token audience mismatch');
        }
        if (empty($arr['sub'])) {
            throw new \RuntimeException('authio: token missing sub');
        }
        $this->assertTenant($arr);

        return $arr;
    }

    /**
     * Tenant binding (security audit 2026-09-18).
     *
     * Signature, issuer and audience prove a token came from Authio, not
     * that it was minted for THIS customer: auth-core signs every tenant
     * with one platform key under one fixed issuer/audience, so
     * project_id is the only claim that tells two tenants apart. Sign-up
     * is self-serve, so anyone can create ceo@your-company.com in their
     * own project and present the resulting token here.
     *
     * With no project configured this warns once and stays permissive, so
     * upgrading the package cannot sign anyone out on its own.
     *
     * @param array<string, mixed> $claims
     */
    private function assertTenant(array $claims): void
    {
        if ($this->projectId === null || $this->projectId === '') {
            if (!self::$warnedNoProject) {
                self::$warnedNoProject = true;
                trigger_error(
                    'authio: no project_id configured, so tokens are not checked against your '
                    . 'tenant. Any Authio-issued token will verify here, including one minted in '
                    . "someone else's project. Set AUTHIO_PROJECT_ID or pass project_id.",
                    E_USER_WARNING,
                );
            }

            return;
        }

        $claimed = isset($claims['project_id']) ? (string) $claims['project_id'] : null;
        if ($claimed !== $this->projectId) {
            throw new \RuntimeException(
                'authio: token was issued for project ' . var_export($claimed, true)
                . ', not ' . var_export($this->projectId, true),
            );
        }
    }

    /**
     * @return array<string, \Firebase\JWT\Key>
     */
    private function getKeys(): array
    {
        $now = time();
        if ($this->keys !== null && $now - $this->fetchedAt < self::CACHE_TTL) {
            return $this->keys;
        }
        if ($this->keys !== null && $now - $this->fetchedAt < self::COOLDOWN) {
            return $this->keys;
        }
        $url = $this->apiUrl . '/v1/auth/.well-known/jwks.json';
        $res = $this->http->get($url, ['headers' => ['accept' => 'application/json']]);
        $jwks = json_decode((string) $res->getBody(), true);
        if (!is_array($jwks) || empty($jwks['keys'])) {
            throw new \RuntimeException("authio: invalid JWKS at $url");
        }
        $this->keys = JWK::parseKeySet($jwks, 'EdDSA');
        $this->fetchedAt = $now;

        return $this->keys;
    }
}

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

    /** @var array<string, \Firebase\JWT\Key>|null */
    private ?array $keys = null;
    private int $fetchedAt = 0;

    public function __construct(
        private readonly string $apiUrl,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly HttpClient $http,
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
        if (isset($arr['iss']) && $arr['iss'] !== $this->issuer) {
            throw new \RuntimeException('authio: token issuer mismatch');
        }
        if (isset($arr['aud'])) {
            $aud = $arr['aud'];
            $audList = is_array($aud) ? $aud : [$aud];
            if (!in_array($this->audience, $audList, true)) {
                throw new \RuntimeException('authio: token audience mismatch');
            }
        }
        if (empty($arr['sub'])) {
            throw new \RuntimeException('authio: token missing sub');
        }

        return $arr;
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

<?php

declare(strict_types=1);

namespace Authio\Tests;

use Authio\Authio;
use Authio\Session;
use PHPUnit\Framework\TestCase;

final class AuthioTest extends TestCase
{
    public function testVerifyTokenReturnsNullForEmpty(): void
    {
        $authio = new Authio(['api_key' => 'sk_test_abc']);
        self::assertNull($authio->verifyToken(null));
        self::assertNull($authio->verifyToken(''));
    }

    public function testVerifyTokenReturnsNullForInvalidJwt(): void
    {
        $authio = new Authio(['api_key' => 'sk_test_abc']);
        // Random non-JWT string should fail verifier and return null.
        self::assertNull($authio->verifyToken('not-a-real-jwt'));
    }

    public function testSessionShape(): void
    {
        $s = new Session(
            sessionId: 'sess_1',
            userId: 'user_1',
            orgId: 'org_1',
            role: 'admin',
            expiresAt: '2026-05-21T12:00:00+00:00',
            claims: ['plan' => 'pro'],
        );
        $arr = $s->toArray();
        self::assertSame('user_1', $arr['user_id']);
        self::assertSame('org_1', $arr['org_id']);
        self::assertSame('admin', $arr['role']);
        self::assertSame(['plan' => 'pro'], $arr['claims']);
    }

    public function testGetters(): void
    {
        $authio = new Authio([
            'api_key' => 'sk_test',
            'api_url' => 'https://example.test/',
            'publishable_key' => 'pk_test_xyz',
        ]);
        // Trailing slash stripped.
        self::assertSame('https://example.test', $authio->getApiUrl());
        self::assertSame('pk_test_xyz', $authio->getPublishableKey());
    }
}

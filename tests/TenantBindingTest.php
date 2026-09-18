<?php

declare(strict_types=1);

namespace Authio\Tests;

use Authio\Authio;
use Authio\JwksVerifier;
use GuzzleHttp\Client as HttpClient;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionProperty;

/**
 * Tenant binding (security audit 2026-09-18).
 *
 * Signature, issuer and audience are identical for every Authio tenant —
 * auth-core signs the whole platform with one key under one fixed
 * issuer/audience. project_id is the only claim that distinguishes a
 * token minted for this customer from one minted in someone else's
 * (self-serve, free) Authio project.
 */
final class TenantBindingTest extends TestCase
{
    /** @param array<string, mixed> $claims */
    private function assertTenantOn(?string $projectId, array $claims): void
    {
        $verifier = new JwksVerifier(
            'https://identity.authio.com',
            'https://identity.authio.com',
            'authio',
            new HttpClient(),
            $projectId,
        );
        $method = (new ReflectionClass(JwksVerifier::class))->getMethod('assertTenant');
        $method->setAccessible(true);
        $method->invoke($verifier, $claims);
    }

    private function resetWarnLatch(): void
    {
        $p = new ReflectionProperty(JwksVerifier::class, 'warnedNoProject');
        $p->setAccessible(true);
        $p->setValue(null, false);
    }

    public function testRejectsTokenMintedInAnotherProject(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/was issued for project/');
        $this->assertTenantOn('proj_victim', ['project_id' => 'proj_attacker']);
    }

    public function testRejectsTokenWithNoProjectIdClaim(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/was issued for project/');
        $this->assertTenantOn('proj_victim', ['sub' => 'user_1']);
    }

    public function testAcceptsTokenForConfiguredProject(): void
    {
        $this->assertTenantOn('proj_victim', ['project_id' => 'proj_victim']);
        self::assertTrue(true, 'no exception thrown');
    }

    public function testStaysPermissiveButWarnsWhenUnconfigured(): void
    {
        $this->resetWarnLatch();
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            $warnings[] = $msg;

            return true;
        }, E_USER_WARNING);
        try {
            $this->assertTenantOn(null, ['project_id' => 'proj_anyone']);
        } finally {
            restore_error_handler();
        }
        self::assertCount(1, $warnings);
        self::assertMatchesRegularExpression('/no project_id configured/', $warnings[0]);
    }

    public function testClientReadsProjectIdFromEnv(): void
    {
        putenv('AUTHIO_PROJECT_ID=proj_from_env');
        try {
            $authio = new Authio(['api_key' => 'sk_test_abc']);
            $verifier = (new ReflectionProperty(Authio::class, 'verifier'));
            $verifier->setAccessible(true);
            $prop = new ReflectionProperty(JwksVerifier::class, 'projectId');
            $prop->setAccessible(true);
            self::assertSame('proj_from_env', $prop->getValue($verifier->getValue($authio)));
        } finally {
            putenv('AUTHIO_PROJECT_ID');
        }
    }

    public function testExplicitProjectIdWinsOverEnv(): void
    {
        putenv('AUTHIO_PROJECT_ID=proj_from_env');
        try {
            $authio = new Authio(['api_key' => 'sk_test_abc', 'project_id' => 'proj_explicit']);
            $verifier = (new ReflectionProperty(Authio::class, 'verifier'));
            $verifier->setAccessible(true);
            $prop = new ReflectionProperty(JwksVerifier::class, 'projectId');
            $prop->setAccessible(true);
            self::assertSame('proj_explicit', $prop->getValue($verifier->getValue($authio)));
        } finally {
            putenv('AUTHIO_PROJECT_ID');
        }
    }
}

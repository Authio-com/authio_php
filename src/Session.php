<?php

declare(strict_types=1);

namespace Authio;

/**
 * A verified Authio session. `userId` is always set; `orgId` may be null
 * when the user authenticated but has not yet selected one of their
 * organizations.
 */
final class Session
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly string $sessionId,
        public readonly string $userId,
        public readonly ?string $orgId,
        public readonly ?string $role,
        public readonly string $expiresAt,
        public readonly array $claims = [],
        public readonly bool $isImpersonation = false,
        public readonly ?string $impersonatorEmail = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'session_id' => $this->sessionId,
            'user_id' => $this->userId,
            'org_id' => $this->orgId,
            'role' => $this->role,
            'expires_at' => $this->expiresAt,
            'claims' => $this->claims,
            'is_impersonation' => $this->isImpersonation,
            'impersonator_email' => $this->impersonatorEmail,
        ];
    }
}

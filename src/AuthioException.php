<?php

declare(strict_types=1);

namespace Authio;

class AuthioException extends \RuntimeException
{
    public function __construct(
        public readonly string $authioCode,
        string $message,
        public readonly int $status = 500,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $status, $previous);
    }
}

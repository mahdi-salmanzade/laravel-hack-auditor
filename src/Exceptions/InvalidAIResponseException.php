<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Exceptions;

use RuntimeException;

final class InvalidAIResponseException extends RuntimeException
{
    /**
     * Create an exception for a malformed AI response.
     */
    public static function malformed(string $reason, string $rawResponse = ''): self
    {
        $message = "Invalid AI response: {$reason}";

        if ($rawResponse !== '') {
            $truncated = mb_substr($rawResponse, 0, 500);
            $message .= " | Raw (truncated): {$truncated}";
        }

        return new self($message);
    }

    /**
     * Create an exception for missing required fields.
     */
    public static function missingField(string $field): self
    {
        return new self("Invalid AI response: missing required field \"{$field}\".");
    }

    /**
     * Create an exception for invalid field types.
     */
    public static function invalidFieldType(string $field, string $expected, string $actual): self
    {
        return new self("Invalid AI response: field \"{$field}\" expected {$expected}, got {$actual}.");
    }
}

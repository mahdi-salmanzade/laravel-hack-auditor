<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Exceptions;

use Mahdi\HackAuditor\Support\UsageTracker;
use RuntimeException;

final class TokenLimitExceededException extends RuntimeException
{
    /**
     * Create a new TokenLimitExceededException.
     */
    public function __construct(
        public readonly UsageTracker $tracker,
        public readonly int $filesScanned,
        public readonly int $filesSkipped,
    ) {
        $used = number_format($tracker->totalTokens());
        $limit = number_format($tracker->getTokenLimit());

        parent::__construct(
            "Token limit reached: {$used} / {$limit} tokens used. "
            ."{$filesScanned} files scanned, {$filesSkipped} files skipped.",
        );
    }
}

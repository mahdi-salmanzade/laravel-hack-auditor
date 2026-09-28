<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

use Illuminate\Support\Facades\Log;
use Throwable;

enum SeverityLevel: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';

    /**
     * Return the ANSI color name for console output.
     */
    public function color(): string
    {
        return match ($this) {
            self::Critical => 'red',
            self::High => 'yellow',
            self::Medium => 'blue',
            self::Low => 'gray',
        };
    }

    /**
     * Return an emoji representing the severity.
     */
    public function emoji(): string
    {
        return match ($this) {
            self::Critical => '🔴',
            self::High => '🟠',
            self::Medium => '🟡',
            self::Low => '🟢',
        };
    }

    /**
     * Return a numeric weight for scoring.
     */
    public function weight(): int
    {
        return match ($this) {
            self::Critical => 40,
            self::High => 20,
            self::Medium => 10,
            self::Low => 5,
        };
    }

    /**
     * Return a styled label for console output.
     */
    public function label(): string
    {
        return match ($this) {
            self::Critical => "<fg={$this->color()};options=bold>{$this->emoji()} CRITICAL</>",
            self::High => "<fg={$this->color()};options=bold>{$this->emoji()} HIGH</>",
            self::Medium => "<fg={$this->color()}>{$this->emoji()} MEDIUM</>",
            self::Low => "<fg={$this->color()}>{$this->emoji()} LOW</>",
        };
    }

    /**
     * Case-insensitive factory with fallback to Low.
     *
     * Models do not stick to the four canonical words: "Severe", "moderate",
     * "Important" and "Informational" all turn up in real responses. Before the
     * alias table those silently became Low, which quietly demoted a severe
     * finding below the fail-on threshold. Anything still unmapped after the
     * aliases falls back to Low (never dropped) and is logged, so a new model
     * vocabulary shows up in the log instead of in a missed CI gate.
     */
    public static function fromString(string $value): self
    {
        $resolved = self::tryFromString($value);

        if ($resolved !== null) {
            return $resolved;
        }

        self::logUnmapped($value);

        return self::Low;
    }

    /**
     * Resolve a severity word or alias, or null when it is not recognised.
     */
    public static function tryFromString(string $value): ?self
    {
        $normalized = strtolower(trim($value));

        foreach (self::cases() as $case) {
            if ($case->value === $normalized) {
                return $case;
            }
        }

        return match ($normalized) {
            'severe', 'crit', 'blocker', 'p0' => self::Critical,
            'important', 'major', 'serious' => self::High,
            'moderate', 'med', 'warning' => self::Medium,
            'info', 'informational', 'minor', 'note', 'trivial' => self::Low,
            default => null,
        };
    }

    /**
     * Record an unmapped severity word without letting logging break parsing.
     *
     * Called from pure enum code that also runs outside a booted Laravel app
     * (unit tests, the standalone benchmark), where the Log facade has no root.
     */
    private static function logUnmapped(string $value): void
    {
        try {
            Log::warning('[HackAuditor] Unrecognised severity; defaulting to low', [
                'severity' => $value,
            ]);
        } catch (Throwable) {
            // No container bound — nothing to log to.
        }
    }
}

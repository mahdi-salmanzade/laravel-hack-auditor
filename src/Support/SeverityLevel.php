<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

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
     */
    public static function fromString(string $value): self
    {
        $normalized = strtolower(trim($value));

        foreach (self::cases() as $case) {
            if ($case->value === $normalized) {
                return $case;
            }
        }

        return self::Low;
    }
}

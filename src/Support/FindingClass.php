<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

/**
 * What a finding CLAIMS about the code.
 *
 * Severity answers "how bad is this if it is real". It does not answer "am I
 * sure this is real", and collapsing the two into one axis is what produced a
 * 99.7% false-positive rate: a detector that could not prove exploitability
 * still asserted a HIGH vulnerability, and users applied its fix.
 *
 * So findings come in two classes, and they are counted, rendered and gated
 * separately:
 *
 *  - Vulnerability: an ASSERTION. The detector can print an evidence chain of
 *    resolved facts — attacker-controlled source at file:line, reaching a sink
 *    at file:line, with no sanitiser or guard on the path. If any link in that
 *    chain is unproven, the finding is not this class.
 *  - Review: a QUESTION. Security-sensitive code a human should look at. It is
 *    excluded from the vulnerability count, from the security score and from
 *    the exit code, and it NEVER carries a suggested fix — a fix implies a
 *    diagnosis the evidence does not support.
 *
 * This mirrors SonarQube's split between a Vulnerability and a Security
 * Hotspot, Semgrep's `metadata.subcategory: audit` vs `vuln`, and CodeQL's
 * `@precision` axis sitting orthogonal to `@problem.severity`.
 */
enum FindingClass: string
{
    /**
     * An asserted vulnerability, backed by a resolved evidence chain.
     */
    case Vulnerability = 'vulnerability';

    /**
     * A question for a human. Never asserted, never scored, never fixed for them.
     */
    case Review = 'review';

    /**
     * Whether findings of this class are counted as vulnerabilities.
     */
    public function isVulnerability(): bool
    {
        return $this === self::Vulnerability;
    }

    /**
     * Whether findings of this class are questions rather than assertions.
     */
    public function isReview(): bool
    {
        return $this === self::Review;
    }

    /**
     * Whether a finding of this class may carry a suggested fix at all.
     *
     * Confidence must also be Proven — see Confidence::maySuggestFix(). A fix
     * attached to a question is how "add $this->authorize('delete', $contract)"
     * reached a controller where $contract does not exist in that scope.
     */
    public function maySuggestFix(): bool
    {
        return $this === self::Vulnerability;
    }

    /**
     * Whether findings of this class may affect the security score and the
     * process exit code.
     */
    public function affectsScore(): bool
    {
        return $this === self::Vulnerability;
    }

    /**
     * Short human label, e.g. for JSON consumers and plain-text digests.
     */
    public function label(): string
    {
        return match ($this) {
            self::Vulnerability => 'Confirmed vulnerability',
            self::Review => 'Needs review',
        };
    }

    /**
     * Section heading used by the console and HTML renderers.
     */
    public function heading(): string
    {
        return match ($this) {
            self::Vulnerability => 'Confirmed vulnerabilities',
            self::Review => 'Needs review',
        };
    }

    /**
     * One line explaining what the reader is looking at, and what it is not.
     */
    public function explanation(): string
    {
        return match ($this) {
            self::Vulnerability => 'Asserted findings: the analyzer resolved a source, a sink and an unguarded path between them.',
            self::Review => 'Open questions, not assertions. The analyzer could not prove these are exploitable, so it does not claim they are and offers no fix. A human decides.',
        };
    }

    /**
     * Case-insensitive factory.
     *
     * Anything unrecognised becomes Review. An unknown class must never be
     * promoted into an assertion the evidence may not support.
     */
    public static function fromString(string $value): self
    {
        $normalized = strtolower(trim($value));

        foreach (self::cases() as $case) {
            if ($case->value === $normalized) {
                return $case;
            }
        }

        return self::Review;
    }
}

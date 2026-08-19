<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

/**
 * How sure the analyzer is that a finding is real.
 *
 * Orthogonal to SeverityLevel: severity answers "how bad if real", confidence
 * answers "how sure am I". Lowering a HIGH to a MEDIUM to express doubt is a
 * category error — it tells the reader the impact shrank when what actually
 * shrank was the evidence.
 *
 *  - Proven:   every link of the evidence chain was resolved from the analysed
 *              code. Only this level may be class Vulnerability with a fix.
 *  - Probable: strong signal, but at least one link is inferred. Still reported
 *              as a vulnerability. A deterministic detector must not TEMPLATE a
 *              fix at this level — it cannot prove the identifiers it would
 *              interpolate — but the level itself does not strip a fix, because
 *              AI-authored findings default here and their fix is prose about
 *              their own finding rather than an interpolated template.
 *  - Possible: a pattern worth a human's attention and nothing more. Review
 *              class only — it is a question, not a finding.
 *
 * Anything below Possible is not emitted at all. A finding the analyzer cannot
 * justify is deleted, not downgraded.
 */
enum Confidence: string
{
    /**
     * Every link of the evidence chain was resolved from the analysed code.
     */
    case Proven = 'proven';

    /**
     * Strong signal with at least one inferred link.
     */
    case Probable = 'probable';

    /**
     * Worth a human's attention; not evidence of a vulnerability.
     */
    case Possible = 'possible';

    /**
     * Numeric rank for ordering and comparison (higher is more certain).
     */
    public function rank(): int
    {
        return match ($this) {
            self::Proven => 3,
            self::Probable => 2,
            self::Possible => 1,
        };
    }

    /**
     * Whether this confidence is at least as strong as the given level.
     */
    public function atLeast(self $minimum): bool
    {
        return $this->rank() >= $minimum->rank();
    }

    /**
     * The strongest class a finding at this confidence is allowed to claim.
     *
     * Possible evidence can only ever ask a question.
     */
    public function strongestClass(): FindingClass
    {
        return $this === self::Possible
            ? FindingClass::Review
            : FindingClass::Vulnerability;
    }

    /**
     * Whether a finding at this confidence may carry a suggested fix.
     *
     * Only Proven. A fix names identifiers, and naming an identifier the
     * analyzer did not resolve is how a suggested `authorize()` call ended up
     * referencing a variable that only exists inside a closure. A missing fix
     * is fine; a wrong fix is a catastrophe.
     */
    public function maySuggestFix(): bool
    {
        return $this === self::Proven;
    }

    /**
     * Short human label for reports.
     */
    public function label(): string
    {
        return match ($this) {
            self::Proven => 'proven',
            self::Probable => 'probable',
            self::Possible => 'possible',
        };
    }

    /**
     * One line describing what this confidence level means to a reader.
     */
    public function explanation(): string
    {
        return match ($this) {
            self::Proven => 'Source, sink and the unguarded path between them were all resolved in the analysed code.',
            self::Probable => 'Strong evidence, but at least one link in the chain is inferred rather than resolved.',
            self::Possible => 'A pattern worth checking. The analyzer has no evidence that it is exploitable.',
        };
    }

    /**
     * Case-insensitive factory.
     *
     * Anything unrecognised becomes Possible — the weakest claim — so a typo
     * or a future value can never inflate a finding into an assertion.
     */
    public static function fromString(string $value): self
    {
        $normalized = strtolower(trim($value));

        foreach (self::cases() as $case) {
            if ($case->value === $normalized) {
                return $case;
            }
        }

        return self::Possible;
    }
}

<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * A trust verdict about one expression, with the evidence behind it.
 *
 * Every judgement must be able to explain itself in a sentence that is true of
 * the analysed code — that sentence is what a finding quotes as proof.
 *
 * TWO DIMENSIONS, NOT ONE
 * -----------------------
 * `trust` answers "is any part of this value attacker supplied?".
 * `reach`  answers "how much of the value can the attacker actually decide?".
 *
 * They are different questions and collapsing them is how
 *
 *     Http::get(config('services.crm.base_url').'/v3/contacts/'.$id)
 *
 * came to be reported as "a client can steer the request at internal services
 * / 169.254.169.254". The scheme, host and port of that URL come from server
 * configuration; `$id` is appended AFTER a literal "/" and can therefore only
 * ever land in the path. A path segment cannot change the authority of a URL,
 * so the SSRF claim was not merely over-severe — it was false.
 *
 * `reach` records that distinction:
 *
 *   REACH_FULL — the attacker decides the whole value, including any leading
 *                scheme/host when it is used as a URL. This is a real taint and
 *                `isTainted()` is true.
 *   REACH_PATH — the value begins with a server-controlled origin that is
 *                already terminated by a path separator, so the attacker's data
 *                can only influence the trailing path or query. Still worth a
 *                human look (path traversal, parameter injection), never proof
 *                of SSRF-to-internal-services.
 *
 * `isTainted()` is deliberately FALSE for REACH_PATH: a detector that asks
 * "is this attacker controlled?" and then asserts a vulnerability must not be
 * handed a half-truth. A detector that wants to raise a REVIEW-class question
 * asks `carriesTaint()` and reads `reach`.
 */
final class TaintJudgement
{
    /** The attacker decides the entire value. */
    public const REACH_FULL = 'full';

    /**
     * The attacker's data is appended after a server-controlled origin and a
     * path separator: it can shape the path or query and nothing else.
     */
    public const REACH_PATH = 'path';

    private function __construct(
        public readonly InputTrust $trust,
        public readonly string $evidence,
        public readonly ?string $source,
        public readonly bool $validated,
        public readonly string $reach = self::REACH_FULL,
    ) {}

    public static function tainted(string $evidence, ?string $source = null, bool $validated = false, string $reach = self::REACH_FULL): self
    {
        return new self(InputTrust::Tainted, $evidence, $source, $validated, $reach);
    }

    public static function trusted(string $evidence, ?string $source = null): self
    {
        return new self(InputTrust::Trusted, $evidence, $source, false);
    }

    public static function unknown(string $evidence = 'the origin of this value is not determinable'): self
    {
        return new self(InputTrust::Unknown, $evidence, null, false);
    }

    /**
     * Attacker control over the WHOLE value — the only verdict that may back an
     * asserted vulnerability.
     */
    public function isTainted(): bool
    {
        return $this->trust->isTainted() && $this->reach === self::REACH_FULL;
    }

    /**
     * Attacker data is somewhere inside this value, whatever it can reach.
     * Use this to raise a question, never to assert a vulnerability.
     */
    public function carriesTaint(): bool
    {
        return $this->trust->isTainted();
    }

    /**
     * Attacker data that is confined to the path/query of a server-fixed
     * origin. Review-worthy, but it cannot redirect a request to another host.
     */
    public function isPathOnly(): bool
    {
        return $this->trust->isTainted() && $this->reach === self::REACH_PATH;
    }

    public function isTrusted(): bool
    {
        return $this->trust->isTrusted();
    }

    public function isUnknown(): bool
    {
        return $this->trust === InputTrust::Unknown;
    }

    /**
     * Re-label a judgement while keeping its verdict, for propagation through
     * a variable or an expression ("$url is assigned from ...").
     */
    public function withEvidence(string $evidence): self
    {
        return new self($this->trust, $evidence, $this->source, $this->validated, $this->reach);
    }

    /**
     * Narrow a taint to the path/query of a server-controlled origin.
     *
     * Only ever narrows: a judgement that is not tainted is returned unchanged,
     * so this can never manufacture a taint that was not proven.
     */
    public function confinedToPath(string $evidence): self
    {
        if (! $this->trust->isTainted()) {
            return $this;
        }

        return new self($this->trust, $evidence, $this->source, $this->validated, self::REACH_PATH);
    }

    /**
     * Combine the operands of a composite expression (concatenation,
     * interpolation, ternary). Tainted dominates; otherwise a single unknown
     * operand makes the whole expression unknown.
     *
     * Reach is combined too, and the WIDEST reach wins: one operand the
     * attacker fully controls makes the whole expression fully controlled, even
     * if another operand is only path-deep.
     *
     * @param  array<int, self>  $judgements
     */
    public static function combine(array $judgements, string $evidence): self
    {
        $sawUnknown = false;
        $pathOnly = null;

        foreach ($judgements as $judgement) {
            if ($judgement->carriesTaint()) {
                if ($judgement->reach === self::REACH_FULL) {
                    return self::tainted($evidence, $judgement->source, $judgement->validated);
                }

                $pathOnly ??= $judgement;

                continue;
            }

            if ($judgement->isUnknown()) {
                $sawUnknown = true;
            }
        }

        if ($pathOnly !== null) {
            return self::tainted($evidence, $pathOnly->source, $pathOnly->validated, self::REACH_PATH);
        }

        if ($judgements === [] || $sawUnknown) {
            return self::unknown($evidence);
        }

        return self::trusted($evidence);
    }
}

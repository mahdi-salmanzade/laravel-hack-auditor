<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * The trust of every local variable in one method body, recorded per
 * assignment so a use site is matched with the assignment that reaches it.
 *
 * Line-ordered lookup is the point. A variable taken from request input at
 * line 10 and reassigned from config() at line 14 is TAINTED at line 12 and
 * TRUSTED at line 16. Collapsing that into a single per-variable verdict
 * invents vulnerabilities in code that fixed itself two lines later.
 */
final class TaintState
{
    /**
     * @var array<string, array<int, array{line: int, judgement: TaintJudgement}>>
     */
    private array $variables = [];

    public function __construct(public readonly MethodShape $method) {}

    public function record(string $name, int $line, TaintJudgement $judgement): void
    {
        $this->variables[$name][] = ['line' => $line, 'judgement' => $judgement];
    }

    /**
     * The verdict for a variable at a given line, or null when nothing is known.
     */
    public function at(string $name, ?int $line = null): ?TaintJudgement
    {
        $name = ltrim($name, '$');
        $found = null;

        foreach ($this->variables[$name] ?? [] as $entry) {
            if ($line !== null && $entry['line'] > $line) {
                continue;
            }

            $found = $entry['judgement'];
        }

        return $found;
    }

    /**
     * Every verdict recorded for a variable, in source order — the trail a
     * finding quotes when it explains where a value came from.
     *
     * @return array<int, array{line: int, judgement: TaintJudgement}>
     */
    public function history(string $name): array
    {
        return $this->variables[ltrim($name, '$')] ?? [];
    }

    /**
     * Whether a variable is provably attacker controlled at a given line.
     */
    public function isTainted(string $name, ?int $line = null): bool
    {
        return $this->at($name, $line)?->isTainted() === true;
    }

    /**
     * Final verdict per variable, keyed by name — useful for reporting and tests.
     *
     * @return array<string, TaintJudgement>
     */
    public function final(): array
    {
        $final = [];

        foreach ($this->variables as $name => $entries) {
            $last = end($entries);

            if ($last !== false) {
                $final[$name] = $last['judgement'];
            }
        }

        return $final;
    }

    /**
     * Names of variables that are attacker controlled at their last assignment.
     *
     * @return array<int, string>
     */
    public function taintedVariables(): array
    {
        $names = [];

        foreach ($this->final() as $name => $judgement) {
            if ($judgement->isTainted()) {
                $names[] = $name;
            }
        }

        return $names;
    }
}

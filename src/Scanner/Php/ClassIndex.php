<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * Cross-file lookup of the classes present in a scan.
 *
 * A single file cannot answer "is App\Models\Room an Eloquent model?" — the
 * answer lives in Room.php. The index resolves ancestry across every parsed
 * file so a receiver type can be classified from what the code actually
 * declares rather than from its name.
 *
 * The index stores node-free ClassSummary objects, NOT ClassShapes. A shape is
 * a view onto live AST nodes, so an index of shapes pins every scanned file's
 * syntax tree in memory — 0.2 MB each, unbounded, fatal past ~640 files. A
 * summary is a few hundred bytes and answers every structural question the
 * index is asked: name, ancestry, interfaces, traits, abstractness. Questions
 * that need a method BODY call find()/resolve(), which re-materialises exactly
 * one class through the bounded parser.
 *
 * Prefer has()/summary()/resolveSummary() when the answer is structural: they
 * touch no AST at all, which is what keeps the hot path (isEloquentClass,
 * isRequestClass, ancestry walks) both cheap and flat in memory.
 *
 * Unanalysable files contribute nothing: an index built from a file that
 * failed to parse behaves exactly as if the file did not exist.
 */
final class ClassIndex
{
    /**
     * @var array<string, ClassSummary>
     */
    private array $byFqcn = [];

    /**
     * @var array<string, array<int, ClassSummary>>
     */
    private array $byShortName = [];

    /**
     * @var array<string, array<int, ClassSummary>>
     */
    private array $byPath = [];

    public function __construct(private readonly ?SourceRepository $sources = null) {}

    /**
     * @param  array<int, ParsedFile>  $files
     */
    public static function build(array $files, ?SourceRepository $sources = null): self
    {
        $index = new self($sources ?? SourceRepository::fromParsedFiles($files));

        foreach ($files as $file) {
            $index->add($file);
        }

        return $index;
    }

    public function add(ParsedFile $file): void
    {
        if (! $file->isAnalysable()) {
            return;
        }

        foreach ($file->classes() as $class) {
            $this->addClass($class);
        }
    }

    /**
     * Record one declared class as a summary. The shape itself is not kept —
     * everything the index needs is copied out of it here, while its nodes are
     * still alive.
     */
    public function addClass(ClassShape $class): void
    {
        $summary = ClassSummary::fromShape($class);

        $this->byFqcn[$summary->fqcn()] = $summary;
        $this->byShortName[$summary->shortName()][] = $summary;
        $this->byPath[$summary->path()][] = $summary;
    }

    /**
     * What a file declares, without opening it.
     *
     * This is what lets a detector decide a file is irrelevant BEFORE paying to
     * parse it. A detector that only reasons about controllers can skip the
     * ~80% of an application's files that declare none, which is the difference
     * between a bounded-memory design that is slower than the unbounded one it
     * replaced and one that is faster.
     *
     * @return array<int, ClassSummary>
     */
    public function summariesIn(string $path): array
    {
        return $this->byPath[$path] ?? [];
    }

    /**
     * Every indexed class, as summaries.
     *
     * @return array<int, ClassSummary>
     */
    public function all(): array
    {
        return array_values($this->byFqcn);
    }

    /**
     * Whether the scan declares this class at all. The cheapest question the
     * index answers, and the one asked most often.
     */
    public function has(string $fqcn): bool
    {
        return isset($this->byFqcn[ltrim($fqcn, '\\')]);
    }

    public function summary(string $fqcn): ?ClassSummary
    {
        return $this->byFqcn[ltrim($fqcn, '\\')] ?? null;
    }

    /**
     * Summary by short name, but ONLY when the name is unambiguous. Two classes
     * sharing a short name means we do not know which one is meant, and a guess
     * is exactly what this layer exists to prevent.
     */
    public function summaryShort(string $shortName): ?ClassSummary
    {
        $matches = $this->byShortName[$shortName] ?? [];

        return count($matches) === 1 ? $matches[0] : null;
    }

    /**
     * Resolve a summary by FQCN first, then by unambiguous short name.
     */
    public function resolveSummary(string $name): ?ClassSummary
    {
        return $this->summary($name) ?? $this->summaryShort(TypeNames::shortName($name));
    }

    /**
     * Re-open a class as a live shape, parsing its file if the bounded cache no
     * longer holds it. Use this only when a method body or an AST node is
     * genuinely needed; every structural question has a summary answer.
     */
    public function find(string $fqcn): ?ClassShape
    {
        return $this->materialise($this->summary($fqcn));
    }

    /**
     * Look up by short name, but ONLY when the name is unambiguous. Two classes
     * sharing a short name means we do not know which one is meant, and a guess
     * is exactly what this layer exists to prevent.
     */
    public function findShort(string $shortName): ?ClassShape
    {
        return $this->materialise($this->summaryShort($shortName));
    }

    /**
     * Resolve a class by FQCN first, then by unambiguous short name.
     */
    public function resolve(string $name): ?ClassShape
    {
        return $this->materialise($this->resolveSummary($name));
    }

    /**
     * The ancestry of a class: itself, then every parent we can follow. The
     * chain terminates at the first parent that is not in the index, but that
     * parent's NAME is still included — vendor base classes (Model,
     * Authenticatable, Controller) are never in a scan yet are exactly what we
     * need to match on.
     *
     * @return array<int, string>
     */
    public function ancestry(string $fqcn): array
    {
        $names = [];
        $current = ltrim($fqcn, '\\');
        $seen = [];

        while ($current !== '' && ! isset($seen[$current])) {
            $seen[$current] = true;
            $names[] = $current;

            $class = $this->summary($current);

            if ($class === null) {
                break;
            }

            $parent = $class->parentClass();

            if ($parent === null) {
                break;
            }

            $current = $parent;
        }

        return $names;
    }

    /**
     * The whole inheritance surface of a class: the class itself, every
     * ancestor, every trait any of them uses, and every trait those traits use.
     *
     * Three lists come back because each answers a different question:
     *
     *  - `shapes`     is what this scan can actually open and inspect.
     *  - `names`      is what the code DECLARES, vendor names included. A
     *                 vendor trait is never a shape — it is not in the scan —
     *                 yet `Illuminate\Foundation\Auth\Access\AuthorizesRequests`
     *                 appearing in this list is the whole proof that
     *                 `$this->authorize()` resolves.
     *  - `unreadable` is the surface this scan could NOT open, which separates
     *                 "nothing provides it" from "we cannot tell".
     *
     * The shapes are materialised here, so an inheritance chain is the only
     * thing held live — a handful of files, not the application.
     *
     * @return array{names: array<int, string>, shapes: array<int, ClassShape>, unreadable: array<int, string>}
     */
    public function chain(string $fqcn): array
    {
        $resolved = $this->chainSummaries($fqcn);
        $shapes = [];

        foreach ($resolved['summaries'] as $summary) {
            $shape = $this->materialise($summary);

            if ($shape !== null) {
                $shapes[] = $shape;
            }
        }

        return [
            'names' => $resolved['names'],
            'shapes' => $shapes,
            'unreadable' => $resolved['unreadable'],
        ];
    }

    /**
     * The inheritance surface without opening a single file.
     *
     * @return array{names: array<int, string>, summaries: array<int, ClassSummary>, unreadable: array<int, string>}
     */
    public function chainSummaries(string $fqcn): array
    {
        $names = [];
        $summaries = [];
        $unreadable = [];
        $seenName = [];
        $seenSummary = [];
        $pending = [ltrim($fqcn, '\\')];

        while ($pending !== []) {
            $current = ltrim(array_shift($pending), '\\');

            if ($current === '' || isset($seenName[$current])) {
                continue;
            }

            $seenName[$current] = true;
            $names[] = $current;

            $summary = $this->resolveSummary($current);

            if ($summary === null) {
                $unreadable[] = $current;

                continue;
            }

            if (isset($seenSummary[$summary->fqcn()])) {
                continue;
            }

            $seenSummary[$summary->fqcn()] = true;
            $summaries[] = $summary;

            $parent = $summary->parentClass();

            if ($parent !== null) {
                $pending[] = $parent;
            }

            foreach ($summary->traits() as $trait) {
                $pending[] = $trait;
            }
        }

        return ['names' => $names, 'summaries' => $summaries, 'unreadable' => $unreadable];
    }

    /**
     * Whether a class is, or descends from, any of the given base classes.
     *
     * @param  array<int, string>  $bases
     */
    public function descendsFromAny(string $fqcn, array $bases): bool
    {
        foreach ($this->ancestry($fqcn) as $name) {
            if (in_array($name, $bases, true)) {
                return true;
            }
        }

        $class = $this->summary($fqcn);

        if ($class === null) {
            return false;
        }

        foreach ($class->interfaces() as $interface) {
            if (in_array($interface, $bases, true)) {
                return true;
            }
        }

        foreach ($class->traits() as $trait) {
            if (in_array($trait, $bases, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Turn a summary back into a live shape. Null when the index was built
     * without a repository (nothing to re-open) or the file no longer parses.
     */
    private function materialise(?ClassSummary $summary): ?ClassShape
    {
        if ($summary === null || $this->sources === null) {
            return null;
        }

        return $this->sources->classShape($summary->path(), $summary->fqcn());
    }
}

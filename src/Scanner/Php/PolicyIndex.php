<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * Maps every model in a scan to the Policy that governs it AND to the exact
 * abilities that Policy declares.
 *
 * "A Policy class exists for this model" is not a finding. "This action needs
 * the `update` ability, the Policy declares `update`, and nothing invokes it"
 * is. Without the ability list, an action such as store() — for which
 * RoomPolicy declares no ability at all — reads as an unenforced policy, and
 * the suggested remedy (`$this->authorize('store', $room)`) references an
 * ability that does not exist and a variable that has not been created yet.
 *
 * The ability list is extracted ONCE, while the policy file is being indexed,
 * and kept as plain strings. Holding the policy's ClassShape instead would pin
 * its whole syntax tree for the length of the scan, which is the retention that
 * made a large application run out of memory. policyFor() re-opens the class
 * through the bounded parser on the rare occasion a caller needs real nodes.
 */
final class PolicyIndex
{
    /**
     * Policy class FQCN => where it lives and what it declares.
     *
     * @var array<string, array{path: string, shortName: string, abilities: array<int, string>}>
     */
    private array $policies = [];

    /**
     * @var array<string, string>
     */
    private array $modelToPolicyKey = [];

    public function __construct(
        private readonly ?SourceRepository $sources = null,
        private readonly PolicyInspector $inspector = new PolicyInspector,
    ) {}

    /**
     * @param  array<int, ParsedFile>  $files
     */
    public static function fromFiles(array $files, ?PolicyInspector $inspector = null, ?SourceRepository $sources = null): self
    {
        $index = new self(
            $sources ?? SourceRepository::fromParsedFiles($files),
            $inspector ?? new PolicyInspector,
        );

        foreach ($files as $file) {
            if (! $file->isAnalysable()) {
                continue;
            }

            foreach ($file->classes() as $class) {
                $index->addPolicy($class);
            }
        }

        return $index;
    }

    public function addPolicy(ClassShape $class): void
    {
        if (! $this->inspector->isPolicy($class)) {
            return;
        }

        $key = $class->fqcn();

        $this->policies[$key] = [
            'path' => $class->file()->path,
            'shortName' => $class->shortName(),
            'abilities' => $this->inspector->abilities($class),
        ];

        $model = $this->inspector->modelFor($class);

        if ($model === null) {
            return;
        }

        $this->modelToPolicyKey[$this->normalise($model)] = $key;
        $this->modelToPolicyKey[$this->normalise(TypeNames::shortName($model))] = $key;
    }

    /**
     * Fully-qualified names of every indexed policy.
     *
     * @return array<int, string>
     */
    public function policyNames(): array
    {
        return array_keys($this->policies);
    }

    public function hasPolicyFor(string $model): bool
    {
        return $this->keyFor($model) !== null;
    }

    /**
     * The policy class governing a model, re-opened through the parser. Returns
     * null when no policy is indexed, or when the index was built without a
     * repository to re-open it from.
     */
    public function policyFor(string $model): ?ClassShape
    {
        $key = $this->keyFor($model);

        if ($key === null || $this->sources === null) {
            return null;
        }

        return $this->sources->classShape($this->policies[$key]['path'], $key);
    }

    /**
     * Short class name of the policy governing a model — the name a finding
     * quotes — without opening the file.
     */
    public function policyNameFor(string $model): ?string
    {
        $key = $this->keyFor($model);

        return $key === null ? null : $this->policies[$key]['shortName'];
    }

    /**
     * Abilities declared by the model's Policy. An empty list means either no
     * Policy or a Policy with no abilities — in both cases there is nothing to
     * enforce and nothing to advise.
     *
     * @return array<int, string>
     */
    public function abilitiesFor(string $model): array
    {
        $key = $this->keyFor($model);

        return $key === null ? [] : $this->policies[$key]['abilities'];
    }

    /**
     * Whether the model's Policy declares a specific ability. This is the
     * question a policy-enforcement detector must ask before reporting
     * anything, and the question the previous implementation never asked.
     */
    public function hasAbility(string $model, string $ability): bool
    {
        foreach ($this->abilitiesFor($model) as $declared) {
            if (strtolower($declared) === strtolower($ability)) {
                return true;
            }
        }

        return false;
    }

    private function keyFor(string $model): ?string
    {
        return $this->modelToPolicyKey[$this->normalise($model)]
            ?? $this->modelToPolicyKey[$this->normalise(TypeNames::shortName($model))]
            ?? null;
    }

    private function normalise(string $name): string
    {
        return strtolower(ltrim($name, '\\'));
    }
}

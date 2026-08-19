<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Benchmark;

use JsonException;
use RuntimeException;

/**
 * Loads and represents the labeled benchmark corpus.
 *
 * The ground truth is a flat list of per-file expectations. Each expectation
 * carries the canonical vulnerability type, an approximate line, a set of
 * accepted synonym types so the matcher can credit findings the AI filed under
 * an adjacent (but defensible) OWASP category, and the ENGINE the gate holds
 * responsible for the label.
 *
 * The engine tag exists so the reproducible half of the scanner can be gated on
 * its own, with no AI provider in the loop: `hack:benchmark --deterministic`
 * scores only the labels tagged 'deterministic'. It is a floor, not a ceiling —
 * a deterministic detector that finds an 'ai'-tagged label is still credited in
 * full-corpus mode.
 */
final readonly class GroundTruth
{
    /**
     * The engine tag meaning "the reproducible, provider-independent detectors
     * are expected to find this without any AI in the loop".
     */
    public const ENGINE_DETERMINISTIC = 'deterministic';

    /**
     * The engine tag for labels only the AI pass is expected to find. Also the
     * default for an untagged label: a label is excluded from the deterministic
     * gate unless it explicitly claims to belong there.
     */
    public const ENGINE_AI = 'ai';

    /**
     * @param  array<int, array{file: string, expected: array<int, array{type: string, line: int, accepted_types: array<int, string>, engine: string}>}>  $samples
     */
    public function __construct(
        public array $samples,
        public int $lineTolerance = 3,
    ) {}

    /**
     * Build a GroundTruth instance from the packaged ground-truth.json fixture.
     */
    public static function default(): self
    {
        return self::fromFile(self::defaultPath());
    }

    /**
     * Absolute path to the packaged ground-truth.json fixture.
     */
    public static function defaultPath(): string
    {
        return dirname(__DIR__, 2).'/tests/Fixtures/benchmark/ground-truth.json';
    }

    /**
     * Absolute path to the directory holding the labeled code samples.
     */
    public static function defaultSamplesPath(): string
    {
        return dirname(__DIR__, 2).'/tests/Fixtures/benchmark/samples';
    }

    /**
     * Build a GroundTruth instance from a ground-truth JSON file on disk.
     */
    public static function fromFile(string $path): self
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw new RuntimeException("Ground truth file not found or unreadable: {$path}");
        }

        $raw = (string) file_get_contents($path);

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException("Invalid JSON in ground truth file {$path}: {$e->getMessage()}", 0, $e);
        }

        return self::fromArray($decoded);
    }

    /**
     * Build a GroundTruth instance from a decoded array structure.
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $lineTolerance = isset($data['line_tolerance']) ? (int) $data['line_tolerance'] : 3;

        /** @var array<int, array<string, mixed>> $rawSamples */
        $rawSamples = is_array($data['samples'] ?? null) ? $data['samples'] : [];

        $samples = [];

        foreach ($rawSamples as $rawSample) {
            $file = (string) ($rawSample['file'] ?? '');

            if ($file === '') {
                continue;
            }

            /** @var array<int, array<string, mixed>> $rawExpected */
            $rawExpected = is_array($rawSample['expected'] ?? null) ? $rawSample['expected'] : [];

            $expected = [];

            foreach ($rawExpected as $entry) {
                $type = strtolower(trim((string) ($entry['type'] ?? '')));

                if ($type === '') {
                    continue;
                }

                /** @var array<int, string> $acceptedRaw */
                $acceptedRaw = is_array($entry['accepted_types'] ?? null) ? $entry['accepted_types'] : [];
                $accepted = array_values(array_unique(array_map(
                    static fn ($t): string => strtolower(trim((string) $t)),
                    $acceptedRaw,
                )));

                if (! in_array($type, $accepted, true)) {
                    $accepted[] = $type;
                }

                $engine = strtolower(trim((string) ($entry['engine'] ?? self::ENGINE_AI)));

                $expected[] = [
                    'type' => $type,
                    'line' => (int) ($entry['line'] ?? 0),
                    'accepted_types' => $accepted,
                    'engine' => $engine === '' ? self::ENGINE_AI : $engine,
                ];
            }

            $samples[] = [
                'file' => $file,
                'expected' => $expected,
            ];
        }

        return new self($samples, $lineTolerance);
    }

    /**
     * A copy of this ground truth keeping only the labels the given engine owns.
     *
     * EVERY sample file is retained, including ones whose labels were all
     * filtered out. Dropping those files would drop them from the corpus, and a
     * finding reported on a file outside the corpus is ignored rather than
     * counted — so filtering by file would quietly stop penalising false
     * positives on exactly the samples the engine is not supposed to flag.
     */
    public function onlyEngine(string $engine): self
    {
        $engine = strtolower(trim($engine));

        $samples = array_map(
            static fn (array $sample): array => [
                'file' => $sample['file'],
                'expected' => array_values(array_filter(
                    $sample['expected'],
                    static fn (array $entry): bool => $entry['engine'] === $engine,
                )),
            ],
            $this->samples,
        );

        return new self($samples, $this->lineTolerance);
    }

    /**
     * The labels this ground truth excludes for a given engine, as
     * "file:line [type]" strings. Rendered by the deterministic gate so the
     * scope of the measurement is stated rather than assumed.
     *
     * @return array<int, string>
     */
    public function labelsExcludedFrom(string $engine): array
    {
        $engine = strtolower(trim($engine));
        $excluded = [];

        foreach ($this->samples as $sample) {
            foreach ($sample['expected'] as $entry) {
                if ($entry['engine'] === $engine) {
                    continue;
                }

                $excluded[] = sprintf('%s:%d [%s]', $sample['file'], $entry['line'], $entry['type']);
            }
        }

        return $excluded;
    }

    /**
     * Total number of expected (labeled) vulnerabilities across all samples.
     */
    public function expectedVulnerabilityCount(): int
    {
        return array_sum(array_map(
            static fn (array $sample): int => count($sample['expected']),
            $this->samples,
        ));
    }

    /**
     * Number of clean samples (those with no expected findings).
     */
    public function cleanSampleCount(): int
    {
        return count(array_filter(
            $this->samples,
            static fn (array $sample): bool => $sample['expected'] === [],
        ));
    }

    /**
     * The set of file keys (relative paths within the samples dir) that make up
     * the corpus.
     *
     * @return array<int, string>
     */
    public function files(): array
    {
        return array_map(
            static fn (array $sample): string => $sample['file'],
            $this->samples,
        );
    }
}

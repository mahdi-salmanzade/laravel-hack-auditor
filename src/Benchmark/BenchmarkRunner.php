<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Benchmark;

use Mahdi\HackAuditor\Scanner\Vulnerability;

/**
 * Scores a set of scanner findings against a labeled ground-truth corpus and
 * produces precision / recall / F1 plus a per-type breakdown.
 *
 * Matching is positional and type-aware:
 *
 *   - Findings and labels are bucketed by their relative path within the samples
 *     directory (NOT basename) so a finding can only ever satisfy a label in the
 *     same file. Keying on the relative path means two corpus files that share a
 *     basename in different subdirectories are scored independently instead of
 *     silently overwriting each other.
 *   - Within a file, each finding is greedily matched to the closest still-open
 *     label whose accepted_types contains the finding's type AND whose line is
 *     within the corpus line tolerance. Closest = smallest line distance.
 *   - A label can be credited at most once (no double-counting one true bug as
 *     several true positives).
 *   - Findings on corpus files that match nothing are false positives.
 *   - Findings on files outside the corpus are ignored (out of scope), so the
 *     score reflects only the labeled samples.
 *   - Labels left unmatched are false negatives.
 *
 * The class performs no I/O and no AI calls, so it is fully deterministic and
 * unit-testable with hand-built finding sets.
 */
final class BenchmarkRunner
{
    public function __construct(
        private readonly GroundTruth $groundTruth,
    ) {}

    /**
     * Score the given findings against the ground truth.
     *
     * @param  array<int, Vulnerability>  $findings
     * @return array{
     *     true_positives: int,
     *     false_positives: int,
     *     false_negatives: int,
     *     precision: float,
     *     recall: float,
     *     f1: float,
     *     expected_total: int,
     *     reported_total: int,
     *     per_type: array<string, array{true_positives: int, false_positives: int, false_negatives: int, precision: float, recall: float, f1: float}>,
     *     matches: array<int, array{file: string, type: string, line: int}>,
     *     false_positive_findings: array<int, array{file: string, type: string, line: int}>,
     *     missed_labels: array<int, array{file: string, type: string, line: int}>
     * }
     */
    public function score(array $findings): array
    {
        $corpusFiles = $this->groundTruth->files();
        $tolerance = $this->groundTruth->lineTolerance;

        $labelsByFile = $this->indexLabelsByFile();
        $findingsByFile = $this->indexFindingsByFile($findings, $corpusFiles);

        $truePositives = 0;
        $falsePositives = 0;
        $falseNegatives = 0;

        /** @var array<string, array{tp: int, fp: int, fn: int}> $perType */
        $perType = [];

        $matches = [];
        $falsePositiveFindings = [];
        $missedLabels = [];

        foreach ($corpusFiles as $file) {
            $labels = $labelsByFile[$file] ?? [];
            $fileFindings = $findingsByFile[$file] ?? [];

            $consumed = array_fill(0, count($labels), false);

            foreach ($fileFindings as $finding) {
                $labelIndex = $this->findBestLabel($finding, $labels, $consumed, $tolerance);

                if ($labelIndex === null) {
                    $falsePositives++;
                    $this->bumpType($perType, $finding['type'], 'fp');
                    $falsePositiveFindings[] = $finding;

                    continue;
                }

                $consumed[$labelIndex] = true;
                $truePositives++;
                // Credit the true positive under the LABEL's canonical type so the
                // per-type breakdown is reported in ground-truth terms.
                $this->bumpType($perType, $labels[$labelIndex]['type'], 'tp');

                $matches[] = [
                    'file' => $file,
                    'type' => $labels[$labelIndex]['type'],
                    'line' => $labels[$labelIndex]['line'],
                ];
            }

            foreach ($labels as $index => $label) {
                if (! $consumed[$index]) {
                    $falseNegatives++;
                    $this->bumpType($perType, $label['type'], 'fn');
                    $missedLabels[] = [
                        'file' => $file,
                        'type' => $label['type'],
                        'line' => $label['line'],
                    ];
                }
            }
        }

        $precision = $this->ratio($truePositives, $truePositives + $falsePositives);
        $recall = $this->ratio($truePositives, $truePositives + $falseNegatives);
        $f1 = $this->f1($precision, $recall);

        return [
            'true_positives' => $truePositives,
            'false_positives' => $falsePositives,
            'false_negatives' => $falseNegatives,
            'precision' => $precision,
            'recall' => $recall,
            'f1' => $f1,
            'expected_total' => $this->groundTruth->expectedVulnerabilityCount(),
            'reported_total' => $truePositives + $falsePositives,
            'per_type' => $this->finalizePerType($perType),
            'matches' => $matches,
            'false_positive_findings' => $falsePositiveFindings,
            'missed_labels' => $missedLabels,
        ];
    }

    /**
     * Find the index of the best matching, still-open label for a finding.
     *
     * Returns the index of the closest (by line distance) label whose
     * accepted_types contains the finding's type and whose line is within
     * tolerance, or null when no eligible label remains.
     *
     * @param  array{file: string, type: string, line: int}  $finding
     * @param  array<int, array{type: string, line: int, accepted_types: array<int, string>}>  $labels
     * @param  array<int, bool>  $consumed
     */
    private function findBestLabel(array $finding, array $labels, array $consumed, int $tolerance): ?int
    {
        $bestIndex = null;
        $bestDistance = PHP_INT_MAX;

        foreach ($labels as $index => $label) {
            if ($consumed[$index]) {
                continue;
            }

            if (! in_array($finding['type'], $label['accepted_types'], true)) {
                continue;
            }

            $distance = abs($finding['line'] - $label['line']);

            if ($distance > $tolerance) {
                continue;
            }

            if ($distance < $bestDistance) {
                $bestDistance = $distance;
                $bestIndex = $index;
            }
        }

        return $bestIndex;
    }

    /**
     * Index ground-truth labels by their relative-path key within the corpus.
     *
     * @return array<string, array<int, array{type: string, line: int, accepted_types: array<int, string>}>>
     */
    private function indexLabelsByFile(): array
    {
        $indexed = [];

        foreach ($this->groundTruth->samples as $sample) {
            $indexed[$this->normalizePath($sample['file'])] = array_values($sample['expected']);
        }

        return $indexed;
    }

    /**
     * Normalize findings into simple shapes bucketed by their corpus file key.
     *
     * Findings are matched to corpus files by their relative path within the
     * samples directory, not by basename, so two corpus files sharing a basename
     * in different subdirectories are scored independently. Findings whose path
     * does not resolve to a corpus file are dropped (out of scope) so the
     * benchmark only scores the labeled samples.
     *
     * @param  array<int, Vulnerability>  $findings
     * @param  array<int, string>  $corpusFiles
     * @return array<string, array<int, array{file: string, type: string, line: int}>>
     */
    private function indexFindingsByFile(array $findings, array $corpusFiles): array
    {
        $corpusKeys = array_map([$this, 'normalizePath'], $corpusFiles);
        $indexed = [];

        foreach ($findings as $finding) {
            $key = $this->resolveCorpusKey($finding->location, $corpusKeys);

            if ($key === null) {
                continue;
            }

            $indexed[$key][] = [
                'file' => $key,
                'type' => $finding->type->value,
                'line' => $finding->line,
            ];
        }

        return $indexed;
    }

    /**
     * Resolve a finding location to the corpus file key it belongs to.
     *
     * A finding's location is the path reported by the scanner (relative to the
     * samples root for corpus scans, or any path during unit testing). It maps to
     * a corpus file when its normalized path equals that file's relative-path key
     * or ends with "/{key}". When several keys match, the longest (most specific)
     * wins, so "b/Foo.php" never collides with a sibling "a/Foo.php" entry.
     *
     * @param  array<int, string>  $corpusKeys
     */
    private function resolveCorpusKey(string $location, array $corpusKeys): ?string
    {
        $normalized = $this->normalizePath($location);

        $best = null;

        foreach ($corpusKeys as $key) {
            if ($normalized === $key || str_ends_with($normalized, '/'.$key)) {
                if ($best === null || strlen($key) > strlen($best)) {
                    $best = $key;
                }
            }
        }

        return $best;
    }

    /**
     * Normalize a path to a forward-slash, leading-slash-free relative key.
     */
    private function normalizePath(string $path): string
    {
        return ltrim(str_replace('\\', '/', $path), '/');
    }

    /**
     * Increment a true-positive, false-positive, or false-negative tally for a type.
     *
     * @param  array<string, array{tp: int, fp: int, fn: int}>  $perType
     * @param  'tp'|'fp'|'fn'  $bucket
     */
    private function bumpType(array &$perType, string $type, string $bucket): void
    {
        if (! isset($perType[$type])) {
            $perType[$type] = ['tp' => 0, 'fp' => 0, 'fn' => 0];
        }

        $perType[$type][$bucket]++;
    }

    /**
     * Convert raw per-type tallies into per-type precision/recall/F1 rows.
     *
     * @param  array<string, array{tp: int, fp: int, fn: int}>  $perType
     * @return array<string, array{true_positives: int, false_positives: int, false_negatives: int, precision: float, recall: float, f1: float}>
     */
    private function finalizePerType(array $perType): array
    {
        ksort($perType);

        $result = [];

        foreach ($perType as $type => $counts) {
            $precision = $this->ratio($counts['tp'], $counts['tp'] + $counts['fp']);
            $recall = $this->ratio($counts['tp'], $counts['tp'] + $counts['fn']);

            $result[$type] = [
                'true_positives' => $counts['tp'],
                'false_positives' => $counts['fp'],
                'false_negatives' => $counts['fn'],
                'precision' => $precision,
                'recall' => $recall,
                'f1' => $this->f1($precision, $recall),
            ];
        }

        return $result;
    }

    /**
     * Safe division that returns 0.0 when the denominator is zero.
     */
    private function ratio(int $numerator, int $denominator): float
    {
        if ($denominator === 0) {
            return 0.0;
        }

        return round($numerator / $denominator, 4);
    }

    /**
     * Harmonic mean of precision and recall, guarding against a zero sum.
     */
    private function f1(float $precision, float $recall): float
    {
        if ($precision + $recall === 0.0) {
            return 0.0;
        }

        return round(2 * ($precision * $recall) / ($precision + $recall), 4);
    }
}

<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Report;

use Composer\InstalledVersions;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\Fingerprint;
use Mahdi\HackAuditor\Support\References;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * Renders a report as SARIF 2.1.0 for GitHub code scanning and other SARIF
 * consumers.
 *
 * Mapping decisions, each made so a dashboard cannot overstate the evidence:
 *
 *  - One rule per vulnerability type. The rule's level and security-severity
 *    come from the WORST confirmed instance of that type, because code
 *    scanning ranks alerts by the rule, not the result.
 *  - Review items are emitted at level "note", tagged "review", and never
 *    raise a rule's security-severity: a question must not surface as a
 *    critical alert.
 *  - partialFingerprints carries the Fingerprint hash, so an alert survives
 *    edits above it and AI rewording instead of re-opening every run.
 *  - Confidence maps to SARIF precision (proven → very-high, probable → high,
 *    possible → medium).
 */
final class SarifReportGenerator
{
    public const string SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

    public const string VERSION = '2.1.0';

    private const string PACKAGE = 'mahdisphp/laravel-hack-auditor';

    private const string INFORMATION_URI = 'https://github.com/mahdi-salmanzade/laravel-hack-auditor';

    /**
     * Render the report as a SARIF JSON document.
     *
     * @param  array<int, Vulnerability>|null  $confirmed  Confirmed findings to emit (defaults to all in the report).
     * @param  array<int, Vulnerability>|null  $reviewItems  Review items to emit (defaults to all in the report).
     */
    public function generate(VulnerabilityReport $report, ?array $confirmed = null, ?array $reviewItems = null): string
    {
        return json_encode(
            $this->toArray($report, $confirmed, $reviewItems),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
        );
    }

    /**
     * Build the SARIF document as an array.
     *
     * @param  array<int, Vulnerability>|null  $confirmed
     * @param  array<int, Vulnerability>|null  $reviewItems
     * @return array<string, mixed>
     */
    public function toArray(VulnerabilityReport $report, ?array $confirmed = null, ?array $reviewItems = null): array
    {
        $confirmed ??= $report->confirmedVulnerabilities();
        $reviewItems ??= $report->reviewItems();

        $rules = $this->buildRules($confirmed, $reviewItems);
        $ruleIndex = array_flip(array_map(static fn (array $rule): string => $rule['id'], $rules));

        $results = [];

        foreach ($confirmed as $finding) {
            $results[] = $this->buildResult($report, $finding, $ruleIndex, isReview: false);
        }

        foreach ($reviewItems as $item) {
            $results[] = $this->buildResult($report, $item, $ruleIndex, isReview: true);
        }

        $driver = [
            'name' => 'Laravel Hack Auditor',
            'informationUri' => self::INFORMATION_URI,
            'rules' => $rules,
        ];

        $version = $this->toolVersion();

        if ($version !== null) {
            $driver['semanticVersion'] = $version;
        }

        $coverage = $report->getCoverage();

        return [
            '$schema' => self::SCHEMA,
            'version' => self::VERSION,
            'runs' => [
                [
                    'tool' => ['driver' => $driver],
                    'invocations' => [
                        [
                            'executionSuccessful' => $report->getTargetError() === null,
                            'toolExecutionNotifications' => $this->buildNotifications($report),
                        ],
                    ],
                    'results' => $results,
                    'properties' => [
                        'overall_score' => $report->scoreIsMeaningful() ? $report->overallScore : null,
                        'score_suppressed' => ! $report->scoreIsMeaningful(),
                        'score_suppression_reason' => $report->scoreSuppressionReason(),
                        'coverage' => $coverage?->toArray(),
                    ],
                ],
            ],
        ];
    }

    /**
     * SARIF level for a confirmed finding of the given severity.
     */
    public static function levelFor(SeverityLevel $severity): string
    {
        // Thresholds on the scoring weight rather than a match on the case, so
        // a severity level added later maps sensibly instead of throwing.
        $weight = $severity->weight();

        return match (true) {
            $weight >= SeverityLevel::High->weight() => 'error',
            $weight >= SeverityLevel::Medium->weight() => 'warning',
            default => 'note',
        };
    }

    /**
     * GitHub code-scanning security-severity score (0.0–10.0) for a severity.
     */
    public static function securitySeverityFor(SeverityLevel $severity): string
    {
        $weight = $severity->weight();

        return match (true) {
            $weight >= SeverityLevel::Critical->weight() => '9.5',
            $weight >= SeverityLevel::High->weight() => '8.0',
            $weight >= SeverityLevel::Medium->weight() => '5.5',
            $weight >= SeverityLevel::Low->weight() => '3.0',
            default => '1.0',
        };
    }

    /**
     * SARIF precision for a confidence level.
     */
    public static function precisionFor(Confidence $confidence): string
    {
        return match ($confidence) {
            Confidence::Proven => 'very-high',
            Confidence::Probable => 'high',
            Confidence::Possible => 'medium',
        };
    }

    /**
     * One rule per vulnerability type present in the output.
     *
     * @param  array<int, Vulnerability>  $confirmed
     * @param  array<int, Vulnerability>  $reviewItems
     * @return array<int, array<string, mixed>>
     */
    private function buildRules(array $confirmed, array $reviewItems): array
    {
        /** @var array<string, array{type: VulnerabilityType, worst: SeverityLevel|null}> $byType */
        $byType = [];

        foreach ($confirmed as $finding) {
            $current = $byType[$finding->type->value]['worst'] ?? null;

            $byType[$finding->type->value] = [
                'type' => $finding->type,
                'worst' => $current === null || $finding->severity->weight() > $current->weight()
                    ? $finding->severity
                    : $current,
            ];
        }

        foreach ($reviewItems as $item) {
            $byType[$item->type->value] ??= ['type' => $item->type, 'worst' => null];
        }

        $rules = [];

        foreach ($byType as $entry) {
            $type = $entry['type'];
            $worst = $entry['worst'];

            $tags = ['security', $type->cweId(), $type->owaspCategory()];
            $properties = ['tags' => $tags];

            // Only confirmed instances may give a rule a security-severity;
            // a type seen only as review items stays a note.
            if ($worst !== null) {
                $properties['security-severity'] = self::securitySeverityFor($worst);
            } else {
                $properties['tags'][] = 'review';
            }

            $rule = [
                'id' => $type->value,
                'name' => $type->name,
                'shortDescription' => ['text' => $type->label()],
                'fullDescription' => ['text' => $type->description()],
                'defaultConfiguration' => ['level' => $worst !== null ? self::levelFor($worst) : 'note'],
                'help' => [
                    'text' => $type->description(),
                    'markdown' => $this->helpMarkdown($type),
                ],
                'properties' => $properties,
            ];

            $cweUrl = References::cweUrl($type);

            if ($cweUrl !== null) {
                $rule['helpUri'] = $cweUrl;
            }

            $rules[] = $rule;
        }

        return $rules;
    }

    /**
     * Build one SARIF result.
     *
     * @param  array<string, int>  $ruleIndex
     * @return array<string, mixed>
     */
    private function buildResult(VulnerabilityReport $report, Vulnerability $finding, array $ruleIndex, bool $isReview): array
    {
        $message = trim($finding->description) !== '' ? $finding->description : $finding->type->label();

        $properties = [
            'severity' => $finding->severity->value,
            'confidence' => $finding->confidence->value,
            'precision' => self::precisionFor($finding->confidence),
            'class' => $finding->findingClass->value,
            'tags' => $isReview ? ['security', 'review'] : ['security'],
        ];

        if ($finding->hasFix()) {
            $properties['suggested_fix'] = $finding->fix;
        }

        if ($finding->taintTrace !== null) {
            $properties['taint_trace'] = $finding->taintTrace;
        }

        return [
            'ruleId' => $finding->type->value,
            'ruleIndex' => $ruleIndex[$finding->type->value] ?? 0,
            'level' => $isReview ? 'note' : self::levelFor($finding->severity),
            'message' => ['text' => $message],
            'locations' => [
                [
                    'physicalLocation' => [
                        'artifactLocation' => [
                            'uri' => $this->relativeUri($finding->location),
                            'uriBaseId' => '%SRCROOT%',
                        ],
                        'region' => ['startLine' => max(1, $finding->line)],
                    ],
                ],
            ],
            'partialFingerprints' => [
                Fingerprint::VERSION => $report->fingerprintOf($finding),
            ],
            'properties' => $properties,
        ];
    }

    /**
     * Surface skipped files and a target error as tool notifications, so a
     * partial run is visible in the SARIF consumer and not only in the log.
     *
     * @return array<int, array<string, mixed>>
     */
    private function buildNotifications(VulnerabilityReport $report): array
    {
        $notifications = [];

        $targetError = $report->getTargetError();

        if ($targetError !== null) {
            $notifications[] = [
                'level' => 'error',
                'message' => ['text' => $targetError],
            ];
        }

        $coverage = $report->getCoverage();

        foreach ($coverage === null ? [] : $coverage->skipped as $entry) {
            $notifications[] = [
                'level' => 'warning',
                'message' => ['text' => 'Not analysed ('.$entry['reason'].'): '.$entry['path']],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $this->relativeUri($entry['path']),
                                'uriBaseId' => '%SRCROOT%',
                            ],
                        ],
                    ],
                ],
            ];
        }

        return $notifications;
    }

    /**
     * Markdown help for a rule: the type description plus its references.
     */
    private function helpMarkdown(VulnerabilityType $type): string
    {
        $lines = [$type->description(), ''];

        foreach (References::for($type) as $reference) {
            $lines[] = '- ['.$reference['title'].']('.$reference['url'].')';
        }

        return rtrim(implode("\n", $lines));
    }

    /**
     * A project-relative, percent-encoded URI for a finding location.
     */
    private function relativeUri(string $location): string
    {
        $path = Fingerprint::normalisePath($location);

        return implode('/', array_map('rawurlencode', explode('/', $path)));
    }

    /**
     * Installed package version, or null when Composer cannot tell.
     */
    private function toolVersion(): ?string
    {
        try {
            $version = InstalledVersions::getPrettyVersion(self::PACKAGE);
        } catch (\Throwable) {
            return null;
        }

        if ($version === null || preg_match('/^v?(\d+\.\d+\.\d+)/', $version, $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }
}

<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Report\SarifReportGenerator;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\Fingerprint;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

function sarifReport(): VulnerabilityReport
{
    $report = new VulnerabilityReport([
        new Vulnerability(VulnerabilityType::SqlInjection, 'app/Http/A.php', 10, SeverityLevel::Medium, 'medium sqli', 'p', 'f'),
        new Vulnerability(VulnerabilityType::SqlInjection, base_path('app/Http/B Controller.php'), 0, SeverityLevel::Critical, 'critical sqli', 'p', 'f', confidence: Confidence::Proven),
        new Vulnerability(VulnerabilityType::Idor, 'app/Http/C.php', 7, SeverityLevel::Critical, 'Is this record owner-checked?', 'p', '', confidence: Confidence::Possible),
    ], 40, 'summary', '');
    $report->setCoverage(new ScanCoverage(4, 3, [['path' => 'app/Http/D.php', 'reason' => ScanCoverage::REASON_TOKEN_LIMIT]]));

    return $report;
}

it('produces a SARIF 2.1.0 document with the required top-level shape', function (): void {
    $sarif = json_decode((new SarifReportGenerator)->generate(sarifReport()), true, flags: JSON_THROW_ON_ERROR);

    expect($sarif['$schema'])->toBe('https://json.schemastore.org/sarif-2.1.0.json')
        ->and($sarif['version'])->toBe('2.1.0')
        ->and($sarif['runs'])->toHaveCount(1)
        ->and($sarif['runs'][0]['tool']['driver'])->toHaveKeys(['name', 'informationUri', 'rules'])
        ->and($sarif['runs'][0])->toHaveKeys(['tool', 'results', 'invocations']);

    foreach ($sarif['runs'][0]['results'] as $result) {
        expect($result)->toHaveKeys(['ruleId', 'ruleIndex', 'level', 'message', 'locations', 'partialFingerprints'])
            ->and($result['message']['text'])->not->toBe('')
            ->and($result['locations'][0]['physicalLocation']['region']['startLine'])->toBeGreaterThanOrEqual(1)
            ->and($result['locations'][0]['physicalLocation']['artifactLocation']['uriBaseId'])->toBe('%SRCROOT%')
            ->and($sarif['runs'][0]['tool']['driver']['rules'][$result['ruleIndex']]['id'])->toBe($result['ruleId']);
    }
});

it('emits one rule per type, levelled by the worst confirmed instance', function (): void {
    $sarif = (new SarifReportGenerator)->toArray(sarifReport());
    $rules = array_column($sarif['runs'][0]['tool']['driver']['rules'], null, 'id');

    expect($rules)->toHaveCount(2)
        ->and($rules['sql_injection']['defaultConfiguration']['level'])->toBe('error')
        ->and($rules['sql_injection']['properties']['security-severity'])->toBe('9.5')
        ->and($rules['sql_injection']['helpUri'])->toBe('https://cwe.mitre.org/data/definitions/89.html')
        ->and($rules['sql_injection']['properties']['tags'])->toBe(['security', 'CWE-89', 'A03:2021 - Injection']);
});

it('never lets a review item raise a rule severity', function (): void {
    $sarif = (new SarifReportGenerator)->toArray(sarifReport());
    $rules = array_column($sarif['runs'][0]['tool']['driver']['rules'], null, 'id');
    $reviewResult = $sarif['runs'][0]['results'][2];

    expect($rules['idor']['defaultConfiguration']['level'])->toBe('note')
        ->and($rules['idor']['properties'])->not->toHaveKey('security-severity')
        ->and($reviewResult['level'])->toBe('note')
        ->and($reviewResult['properties']['tags'])->toContain('review')
        ->and($reviewResult['properties']['class'])->toBe('review')
        ->and($reviewResult['properties']['precision'])->toBe('medium');
});

it('maps locations, fingerprints and precision per result', function (): void {
    $report = sarifReport();
    $sarif = (new SarifReportGenerator)->toArray($report);
    $critical = $sarif['runs'][0]['results'][1];

    expect($critical['level'])->toBe('error')
        ->and($critical['locations'][0]['physicalLocation']['artifactLocation']['uri'])->toBe('app/Http/B%20Controller.php')
        ->and($critical['locations'][0]['physicalLocation']['region']['startLine'])->toBe(1)
        ->and($critical['partialFingerprints'][Fingerprint::VERSION])->toBe($report->fingerprintOf($report->vulnerabilities[1]))
        ->and($critical['properties']['confidence'])->toBe('proven')
        ->and($critical['properties']['precision'])->toBe('very-high')
        ->and($sarif['runs'][0]['results'][0]['level'])->toBe('warning');
});

it('reports skipped files and a withheld score on the run', function (): void {
    $sarif = (new SarifReportGenerator)->toArray(sarifReport());
    $run = $sarif['runs'][0];

    expect($run['properties']['overall_score'])->toBeNull()
        ->and($run['properties']['score_suppressed'])->toBeTrue()
        ->and($run['invocations'][0]['toolExecutionNotifications'][0]['message']['text'])->toContain('app/Http/D.php');
});

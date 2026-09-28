<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Baseline;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-test-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
    $this->baselinePath = $this->tempDir.'/baseline.json';
});

afterEach(function (): void {
    if (is_dir($this->tempDir)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) {
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }

        rmdir($this->tempDir);
    }
});

function makeVulnerability(
    VulnerabilityType $type = VulnerabilityType::SqlInjection,
    string $location = 'app/Http/Controllers/UserController.php',
    int $line = 42,
    SeverityLevel $severity = SeverityLevel::Critical,
    string $description = 'Raw SQL query with user input.',
    string $proof = 'DB::select("SELECT * FROM users WHERE id = $id")',
    string $fix = 'Use parameterized queries.',
): Vulnerability {
    return new Vulnerability(
        type: $type,
        location: $location,
        line: $line,
        severity: $severity,
        description: $description,
        proof: $proof,
        fix: $fix,
    );
}

it('saves a baseline file with correct JSON format', function (): void {
    $vuln = makeVulnerability();
    $report = new VulnerabilityReport(
        vulnerabilities: [$vuln],
        overallScore: 25,
        summary: 'Critical SQL injection found.',
        ctfIdea: '',
    );

    $baseline = new Baseline;
    $baseline->save($report, $this->baselinePath);

    expect(file_exists($this->baselinePath))->toBeTrue();

    $contents = json_decode(file_get_contents($this->baselinePath), true);

    expect($contents)->toBeArray()
        ->toHaveCount(1)
        ->and($contents[0])->toHaveKeys(['fingerprint', 'file', 'line', 'type', 'hash'])
        ->and($contents[0]['file'])->toBe('app/Http/Controllers/UserController.php')
        ->and($contents[0]['line'])->toBe(42)
        ->and($contents[0]['type'])->toBe('sql_injection')
        ->and($contents[0]['hash'])->toBe(md5('Raw SQL query with user input.'));
});

it('loads baseline entries correctly', function (): void {
    $vuln = makeVulnerability();
    $report = new VulnerabilityReport(
        vulnerabilities: [$vuln],
        overallScore: 25,
        summary: 'Found issues.',
        ctfIdea: '',
    );

    $baseline = new Baseline;
    $baseline->save($report, $this->baselinePath);

    $loadedBaseline = new Baseline;
    $loadedBaseline->load($this->baselinePath);

    expect($loadedBaseline->contains($vuln))->toBeTrue();
});

it('contains matches by file, type, and hash', function (): void {
    $vuln = makeVulnerability();
    $report = new VulnerabilityReport(
        vulnerabilities: [$vuln],
        overallScore: 25,
        summary: 'Found issues.',
        ctfIdea: '',
    );

    $baseline = new Baseline;
    $baseline->save($report, $this->baselinePath);
    $baseline->load($this->baselinePath);

    // Same vulnerability should be contained
    expect($baseline->contains($vuln))->toBeTrue();

    // Different type should not be contained
    $differentVuln = makeVulnerability(type: VulnerabilityType::Xss);
    expect($baseline->contains($differentVuln))->toBeFalse();

    // Different file should not be contained
    $differentFileVuln = makeVulnerability(location: 'app/Models/User.php');
    expect($baseline->contains($differentFileVuln))->toBeFalse();

    // A reworded description is the SAME finding: the AI rewords between runs,
    // and matching on the description made accepted findings come back as new.
    $rewordedVuln = makeVulnerability(description: 'Completely different wording.');
    expect($baseline->contains($rewordedVuln))->toBeTrue();

    // A different flagged line (file unreadable here, so the line number is the
    // anchor) is a different finding.
    $differentLineVuln = makeVulnerability(line: 99);
    expect($baseline->contains($differentLineVuln))->toBeFalse();
});

it('filters vulnerabilities returning new findings and suppressed count', function (): void {
    $baselinedVuln = makeVulnerability();
    $report = new VulnerabilityReport(
        vulnerabilities: [$baselinedVuln],
        overallScore: 25,
        summary: 'Found issues.',
        ctfIdea: '',
    );

    $baseline = new Baseline;
    $baseline->save($report, $this->baselinePath);
    $baseline->load($this->baselinePath);

    $newVuln = makeVulnerability(
        type: VulnerabilityType::Xss,
        description: 'XSS in template.',
        severity: SeverityLevel::High,
    );

    $result = $baseline->filter([$baselinedVuln, $newVuln]);

    expect($result)->toHaveKeys(['new', 'suppressed'])
        ->and($result['new'])->toHaveCount(1)
        ->and($result['new'][0]->type)->toBe(VulnerabilityType::Xss)
        ->and($result['suppressed'])->toBe(1);
});

it('returns false for exists when file does not exist', function (): void {
    $baseline = new Baseline;

    expect($baseline->exists($this->baselinePath))->toBeFalse();
});

it('returns true for exists when file exists', function (): void {
    file_put_contents($this->baselinePath, '[]');

    $baseline = new Baseline;

    expect($baseline->exists($this->baselinePath))->toBeTrue();
});

it('loads gracefully when file does not exist', function (): void {
    $baseline = new Baseline;
    $baseline->load($this->tempDir.'/nonexistent-baseline.json');

    $vuln = makeVulnerability();

    expect($baseline->contains($vuln))->toBeFalse();
});

it('saves a fingerprint on every entry', function (): void {
    $vuln = makeVulnerability();
    $report = new VulnerabilityReport([$vuln], 25, '', '');

    (new Baseline)->save($report, $this->baselinePath);
    $contents = json_decode(file_get_contents($this->baselinePath), true);

    expect($contents[0]['fingerprint'])->toBe($report->fingerprintOf($vuln));
});

it('still honours a legacy baseline file written without fingerprints', function (): void {
    file_put_contents($this->baselinePath, json_encode([[
        'file' => 'app/Http/Controllers/UserController.php',
        'line' => 42,
        'type' => 'sql_injection',
        'hash' => md5('Raw SQL query with user input.'),
    ]]));

    $baseline = (new Baseline)->load($this->baselinePath);

    expect($baseline->contains(makeVulnerability()))->toBeTrue()
        ->and($baseline->contains(makeVulnerability(description: 'Reworded.')))->toBeFalse();
});

it('tolerates malformed baseline entries without errors', function (): void {
    file_put_contents($this->baselinePath, json_encode([
        'not-an-array',
        ['file' => 'app/Http/Controllers/UserController.php'],
        ['type' => 'sql_injection', 'hash' => 42],
        ['fingerprint' => ['nested']],
        null,
    ]));

    $baseline = (new Baseline)->load($this->baselinePath);

    expect($baseline->contains(makeVulnerability()))->toBeFalse()
        ->and($baseline->filter([makeVulnerability()])['suppressed'])->toBe(0);
});

it('matches duplicate findings one-to-one when filtering through the owning report', function (): void {
    $first = makeVulnerability(description: 'one');
    $second = makeVulnerability(description: 'two');

    // Only the first of two otherwise-identical findings was accepted.
    $accepted = new VulnerabilityReport([$first], 25, '', '');
    (new Baseline)->save($accepted, $this->baselinePath);

    $current = new VulnerabilityReport([$first, $second], 25, '', '');
    $result = (new Baseline)->load($this->baselinePath)->filter($current->vulnerabilities, $current);

    expect($result['suppressed'])->toBe(1)
        ->and($result['new'])->toBe([$second]);
});

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
        ->and($contents[0])->toHaveKeys(['file', 'line', 'type', 'hash'])
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

    // Different description (different hash) should not be contained
    $differentDescVuln = makeVulnerability(description: 'Completely different issue.');
    expect($baseline->contains($differentDescVuln))->toBeFalse();
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

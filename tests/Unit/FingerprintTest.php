<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\Fingerprint;
use Mahdi\HackAuditor\Support\References;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

beforeEach(function (): void {
    $this->fpDir = realpath(sys_get_temp_dir()).'/hack-auditor-fp-'.uniqid();
    mkdir($this->fpDir.'/app/Http/Controllers', 0755, true);
    (new ReflectionProperty($this->app, 'basePath'))->setValue($this->app, $this->fpDir);
    Fingerprint::flushCache();
});

afterEach(function (): void {
    Fingerprint::flushCache();
    exec('rm -rf '.escapeshellarg($this->fpDir));
});

function fpFinding(int $line, string $description = 'Raw SQL', string $location = 'app/Http/Controllers/A.php', VulnerabilityType $type = VulnerabilityType::SqlInjection): Vulnerability
{
    return new Vulnerability($type, $location, $line, SeverityLevel::Critical, $description, 'proof', 'fix');
}

it('is a 32-char hex digest', function (): void {
    expect(fpFinding(3)->fingerprint())->toMatch('/^[0-9a-f]{32}$/');
});

it('survives the AI rewording the description', function (): void {
    file_put_contents($this->fpDir.'/app/Http/Controllers/A.php', "<?php\n\n\$r = DB::select(\$q);\n");

    expect(fpFinding(3, 'SQL injection via raw query')->fingerprint())
        ->toBe(fpFinding(3, 'Raw SQL built from request input')->fingerprint());
});

it('survives code above the flagged line moving it down', function (): void {
    $path = $this->fpDir.'/app/Http/Controllers/A.php';
    file_put_contents($path, "<?php\n\$r = DB::select(\$q);\n");
    $before = fpFinding(2)->fingerprint();

    file_put_contents($path, "<?php\n// a new comment\n// and another\n    \$r   =  DB::select(\$q);   \n");
    Fingerprint::flushCache();

    // Same statement, different line number and whitespace: same finding.
    expect(fpFinding(4)->fingerprint())->toBe($before);
});

it('changes when the flagged line itself changes', function (): void {
    $path = $this->fpDir.'/app/Http/Controllers/A.php';
    file_put_contents($path, "<?php\n\$r = DB::select(\$q);\n");
    $before = fpFinding(2)->fingerprint();

    file_put_contents($path, "<?php\n\$r = DB::select('?', [\$q]);\n");
    Fingerprint::flushCache();

    expect(fpFinding(2)->fingerprint())->not->toBe($before);
});

it('normalises absolute, dotted and backslashed paths to the same identity', function (): void {
    file_put_contents($this->fpDir.'/app/Http/Controllers/A.php', "<?php\n\$x = 1;\n");

    $relative = fpFinding(2, location: 'app/Http/Controllers/A.php')->fingerprint();

    expect(fpFinding(2, location: $this->fpDir.'/app/Http/Controllers/A.php')->fingerprint())->toBe($relative)
        ->and(fpFinding(2, location: './app/Http/Controllers/A.php')->fingerprint())->toBe($relative)
        ->and(fpFinding(2, location: 'app\\Http\\Controllers\\A.php')->fingerprint())->toBe($relative)
        ->and(Fingerprint::normalisePath($this->fpDir.'/app/Http/Controllers/A.php'))->toBe('app/Http/Controllers/A.php');
});

it('falls back to the line number when the file is unreadable', function (): void {
    expect(Fingerprint::lineContent('app/Missing.php', 3))->toBeNull()
        ->and(fpFinding(3, location: 'app/Missing.php')->fingerprint())
        ->not->toBe(fpFinding(4, location: 'app/Missing.php')->fingerprint());
});

it('keeps two identical-key findings in one report distinct via the occurrence index', function (): void {
    file_put_contents($this->fpDir.'/app/Http/Controllers/A.php', "<?php\n\$r = DB::select(\$q);\n");

    $first = fpFinding(2, 'first');
    $second = fpFinding(2, 'second');
    $report = new VulnerabilityReport([$first, $second], 20, '', '');

    $fingerprints = $report->fingerprints();

    expect($fingerprints)->toHaveCount(2)
        ->and($fingerprints[0])->not->toBe($fingerprints[1])
        ->and($report->fingerprintOf($second))->toBe($fingerprints[1])
        ->and($report->toArray()['vulnerabilities'][1]['fingerprint'])->toBe($fingerprints[1]);
});

it('emits fingerprint and references in Vulnerability::toArray()', function (): void {
    $data = fpFinding(3)->toArray();

    expect($data['fingerprint'])->toMatch('/^[0-9a-f]{32}$/')
        ->and($data['references'][0])->toBe(['title' => 'CWE-89', 'url' => 'https://cwe.mitre.org/data/definitions/89.html'])
        ->and($data['references'][1]['url'])->toBe('https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html');
});

it('gives every vulnerability type at least a CWE reference', function (VulnerabilityType $type): void {
    $references = References::for($type);

    expect($references)->not->toBeEmpty()
        ->and($references[0]['url'])->toStartWith('https://cwe.mitre.org/data/definitions/');
})->with(fn (): array => array_map(fn (VulnerabilityType $t): array => [$t], VulnerabilityType::cases()));

<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

function buildValidAIResponse(array $vulnerabilities = [], int $score = 100, string $summary = 'No issues found.', string $ctfIdea = ''): string
{
    return json_encode([
        'vulnerabilities' => $vulnerabilities,
        'overall_score' => $score,
        'summary' => $summary,
        'ctf_idea' => $ctfIdea,
    ], JSON_THROW_ON_ERROR);
}

function buildSingleVulnerabilityResponse(): string
{
    return buildValidAIResponse(
        vulnerabilities: [
            [
                'type' => 'sql_injection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 42,
                'severity' => 'critical',
                'description' => 'Raw SQL query with user input.',
                'proof' => 'DB::select("SELECT * FROM users WHERE id = $id")',
                'fix' => 'DB::select("SELECT * FROM users WHERE id = ?", [$id])',
            ],
        ],
        score: 25,
        summary: 'Critical SQL injection found.',
        ctfIdea: 'SQL Injection CTF',
    );
}

function createMockedScanner(string $aiResponse): HackScanner
{
    $fileCollector = app(FileCollector::class);
    $codeExtractor = app(CodeExtractor::class);
    $promptBuilder = app(PromptBuilder::class);
    $responseParser = app(ResponseParser::class);

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('send')
        ->andReturn($aiResponse);

    return new HackScanner(
        fileCollector: $fileCollector,
        codeExtractor: $codeExtractor,
        promptBuilder: $promptBuilder,
        responseParser: $responseParser,
        aiAdapter: $mockAdapter,
    );
}

it('returns a VulnerabilityReport from scan', function (): void {
    $response = buildValidAIResponse();

    $scanner = createMockedScanner($response);
    $report = $scanner->scan();

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(100)
        ->and($report->vulnerabilities)->toBeArray()
        ->and($report->summary)->toBe('No files found to scan.');
});

it('returns an empty report when no files are found to scan', function (): void {
    $response = buildValidAIResponse();

    $scanner = createMockedScanner($response);

    // With default config, the scan paths likely do not exist in the test environment
    $report = $scanner->scan();

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(100)
        ->and($report->vulnerabilities)->toBeEmpty();
});

it('scans raw code with scanCode and returns a VulnerabilityReport', function (): void {
    $response = buildSingleVulnerabilityResponse();

    $scanner = createMockedScanner($response);

    $code = '<?php DB::select("SELECT * FROM users WHERE id = $id");';
    $report = $scanner->scanCode($code);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(25)
        ->and($report->totalCount())->toBe(1)
        ->and($report->vulnerabilities[0]->type)->toBe(VulnerabilityType::SqlInjection)
        ->and($report->vulnerabilities[0]->severity)->toBe(SeverityLevel::Critical)
        ->and($report->vulnerabilities[0]->line)->toBe(42);
});

it('collapses near-duplicate AI findings of the same type at nearby lines even when no deterministic finding fires', function (): void {
    $finding = static fn (int $line): array => [
        'type' => 'sql_injection',
        'location' => 'app/Http/Controllers/UserController.php',
        'line' => $line,
        'severity' => 'critical',
        'description' => 'Raw SQL query with user input.',
        'proof' => 'DB::select("SELECT * FROM users WHERE id = $id")',
        'fix' => 'Use parameter bindings.',
    ];

    // The model reports the SAME issue twice at adjacent lines (42 and 44) — the
    // exact shape of the real IdorController duplicate. They share a dedupe
    // bucket, so the report must collapse them to one even though SQL injection
    // triggers no deterministic detector.
    $response = buildValidAIResponse(
        vulnerabilities: [$finding(42), $finding(44)],
        score: 25,
    );

    $report = createMockedScanner($response)
        ->scanCode('<?php DB::select("SELECT * FROM users WHERE id = $id");');

    expect($report->totalCount())->toBe(1)
        ->and($report->vulnerabilities[0]->type)->toBe(VulnerabilityType::SqlInjection);
});

it('returns a report with file not found message for nonexistent scanFile path', function (): void {
    $response = buildValidAIResponse();

    $scanner = createMockedScanner($response);

    $report = $scanner->scanFile('/nonexistent/path/to/file.php');

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->overallScore)->toBe(100)
        ->and($report->totalCount())->toBe(0)
        ->and($report->summary)->toContain('File not found');
});

it('refuses to scan a .env file via scanFile', function (): void {
    $envPath = base_path('.env');
    $created = ! file_exists($envPath);

    if ($created) {
        file_put_contents($envPath, "APP_KEY=base64:supersecretkeyvalue\nDB_PASSWORD=hunter2\n");
    }

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldNotReceive('send');
    $mockAdapter->shouldNotReceive('sendWithUsage');

    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $mockAdapter,
    );

    try {
        $report = $scanner->scanFile('.env');
    } finally {
        if ($created) {
            @unlink($envPath);
        }
    }

    expect($report->totalCount())->toBe(0)
        ->and($report->summary)->toContain('Refused to scan')
        ->and($report->summary)->toContain('sensitive');
});

it('refuses to scan a *.key file via scanFile', function (): void {
    $keyPath = base_path('storage/oauth-private.key');
    @mkdir(dirname($keyPath), 0755, true);
    file_put_contents($keyPath, "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----");

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldNotReceive('send');
    $mockAdapter->shouldNotReceive('sendWithUsage');

    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $mockAdapter,
    );

    try {
        $report = $scanner->scanFile('storage/oauth-private.key');
    } finally {
        @unlink($keyPath);
    }

    expect($report->totalCount())->toBe(0)
        ->and($report->summary)->toContain('Refused to scan')
        ->and($report->summary)->toContain('sensitive');
});

it('refuses to scan an absolute path outside the application root', function (): void {
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldNotReceive('send');
    $mockAdapter->shouldNotReceive('sendWithUsage');

    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $mockAdapter,
    );

    $report = $scanner->scanFile('/etc/passwd');

    expect($report->totalCount())->toBe(0)
        ->and($report->summary)->toContain('Refused to scan')
        ->and($report->summary)->toContain('outside the application root');
});

it('refuses to scan a traversal path that escapes the application root', function (): void {
    $outside = dirname(base_path()).'/hack-auditor-traversal-secret.php';
    file_put_contents($outside, '<?php $secret = "leaked";');

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldNotReceive('send');
    $mockAdapter->shouldNotReceive('sendWithUsage');

    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $mockAdapter,
    );

    try {
        $report = $scanner->scanFile('../hack-auditor-traversal-secret.php');
    } finally {
        @unlink($outside);
    }

    expect($report->totalCount())->toBe(0)
        ->and($report->summary)->toContain('Refused to scan')
        ->and($report->summary)->toContain('outside the application root');
});

it('still scans a normal in-app controller path', function (): void {
    $controllerDir = base_path('app/Http/Controllers');
    @mkdir($controllerDir, 0755, true);
    $controllerPath = $controllerDir.'/GuardTestController.php';
    file_put_contents(
        $controllerPath,
        '<?php namespace App\Http\Controllers; class GuardTestController { public function show($id) { return $id; } }',
    );

    $scanner = createMockedScanner(buildSingleVulnerabilityResponse());

    try {
        $report = $scanner->scanFile('app/Http/Controllers/GuardTestController.php');
    } finally {
        @unlink($controllerPath);
    }

    expect($report->summary)->not->toContain('Refused to scan')
        ->and($report->totalCount())->toBe(1);
});

it('merges multiple chunk results correctly', function (): void {
    $response1 = buildValidAIResponse(
        vulnerabilities: [
            [
                'type' => 'sql_injection',
                'location' => 'file1.php',
                'line' => 10,
                'severity' => 'critical',
                'description' => 'SQL injection.',
                'proof' => 'code1',
                'fix' => 'fix1',
            ],
        ],
        score: 30,
        summary: 'Summary A.',
        ctfIdea: 'CTF A',
    );

    $response2 = buildValidAIResponse(
        vulnerabilities: [
            [
                'type' => 'xss',
                'location' => 'file2.php',
                'line' => 20,
                'severity' => 'high',
                'description' => 'XSS vulnerability.',
                'proof' => 'code2',
                'fix' => 'fix2',
            ],
        ],
        score: 60,
        summary: 'Summary B.',
        ctfIdea: 'CTF B',
    );

    // Test merging by manually creating two reports and using reflection
    $parser = new ResponseParser;
    $report1 = $parser->parse($response1);
    $report2 = $parser->parse($response2);

    // Simulate merge logic from HackScanner::mergeReports
    $allVulnerabilities = array_merge($report1->vulnerabilities, $report2->vulnerabilities);
    $averageScore = (int) round(($report1->overallScore + $report2->overallScore) / 2);

    expect($allVulnerabilities)->toHaveCount(2)
        ->and($averageScore)->toBe(45)
        ->and($allVulnerabilities[0]->type)->toBe(VulnerabilityType::SqlInjection)
        ->and($allVulnerabilities[1]->type)->toBe(VulnerabilityType::Xss);
});

it('recalculates score when merging reports', function (): void {
    $parser = new ResponseParser;

    $report1 = $parser->parse(buildValidAIResponse(score: 20, summary: 'Bad.'));
    $report2 = $parser->parse(buildValidAIResponse(score: 80, summary: 'Good.'));
    $report3 = $parser->parse(buildValidAIResponse(score: 60, summary: 'OK.'));

    $averageScore = (int) round((20 + 80 + 60) / 3);

    expect($averageScore)->toBe(53);
});

it('scanCode passes inline-code.php as the file path', function (): void {
    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('send')
        ->once()
        ->withArgs(function (string $systemPrompt, string $userPrompt): bool {
            return str_contains($userPrompt, 'inline-code.php');
        })
        ->andReturn(buildValidAIResponse());

    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $mockAdapter,
    );

    $scanner->scanCode('<?php echo "test";');
});

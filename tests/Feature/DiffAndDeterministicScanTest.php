<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Mcp\HackAuditorMcpServer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlDetector;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageTracker;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * A deterministic detector that emits one High IDOR for the first file it sees.
 */
final class FirstFileIdorDetector implements AccessControlDetector
{
    public function detect(array $files, AccessControlContext $context): array
    {
        if ($files === []) {
            return [];
        }

        return [
            new Vulnerability(
                type: VulnerabilityType::Idor,
                location: $files[0]->path,
                line: 3,
                severity: SeverityLevel::High,
                description: 'Stub deterministic finding.',
                proof: 'stub',
                fix: '',
            ),
        ];
    }
}

/**
 * A deterministic detector that always crashes.
 */
final class CrashingDetector implements AccessControlDetector
{
    public function detect(array $files, AccessControlContext $context): array
    {
        throw new RuntimeException('detector exploded');
    }
}

function diffScanAiResponse(array $vulnerabilities = [], int $score = 100): string
{
    return json_encode([
        'vulnerabilities' => $vulnerabilities,
        'overall_score' => $score,
        'summary' => 'AI summary.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

function diffScanner(AIAdapter $adapter, ?AccessControlAnalyzer $analyzer = null): HackScanner
{
    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $adapter,
        accessControlAnalyzer: $analyzer ?? new AccessControlAnalyzer([]),
    );

    $scanner->setUsageTracker(new UsageTracker);

    return $scanner;
}

function diffRepoGit(string $directory, string $arguments): void
{
    exec('git -C '.escapeshellarg($directory).' '.$arguments.' 2>&1', $output, $exitCode);

    if ($exitCode !== 0) {
        throw new RuntimeException("git {$arguments} failed: ".implode("\n", $output));
    }
}

function diffRepoWrite(string $path, string $contents): void
{
    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0755, true);
    }

    file_put_contents($path, $contents);
}

beforeEach(function (): void {
    $this->repo = realpath(sys_get_temp_dir()).'/hack-auditor-diff-'.uniqid();
    mkdir($this->repo, 0755, true);
    $this->originalBasePath = $this->app->basePath();

    diffRepoGit($this->repo, 'init -q -b main');
    diffRepoGit($this->repo, 'config user.email test@test.com');
    diffRepoGit($this->repo, 'config user.name Test');
    diffRepoGit($this->repo, 'config commit.gpgsign false');
    diffRepoWrite($this->repo.'/README.md', 'base');
    diffRepoGit($this->repo, 'add .');
    diffRepoGit($this->repo, 'commit -q -m initial');
    diffRepoGit($this->repo, 'checkout -q -b feature');

    foreach (['Alpha', 'Beta', 'Gamma'] as $name) {
        diffRepoWrite(
            $this->repo."/app/Http/Controllers/{$name}Controller.php",
            "<?php\n\nnamespace App\\Http\\Controllers;\n\nclass {$name}Controller\n{\n    public function index(): string\n    {\n        return 'ok';\n    }\n}\n",
        );
    }

    diffRepoGit($this->repo, 'add .');
    diffRepoGit($this->repo, 'commit -q -m change');

    $this->app->setBasePath($this->repo);
    config()->set('hack-auditor.scan.chunk_size', 10);
});

afterEach(function (): void {
    $this->app->setBasePath($this->originalBasePath);
    exec('rm -rf '.escapeshellarg($this->repo));
});

it('scans a diff in one chunked request instead of one request per file', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldReceive('sendWithUsage')->once()->andReturn([
        'text' => diffScanAiResponse(),
        'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 10],
    ]);

    $report = diffScanner($adapter)->scanDiff('main');

    expect($report->getCoverage()->filesDiscovered)->toBe(3)
        ->and($report->getCoverage()->filesAnalyzed)->toBe(3)
        ->and($report->getTargetError())->toBeNull()
        ->and($report->scoreIsMeaningful())->toBeTrue();
});

it('narrows a diff scan to --path', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldReceive('sendWithUsage')->once()->andReturn([
        'text' => diffScanAiResponse(),
        'usage' => ['prompt_tokens' => 1, 'completion_tokens' => 1],
    ]);

    $report = diffScanner($adapter)->scanDiff('main', 'app/Http/Controllers/BetaController.php');

    expect($report->getCoverage()->filesDiscovered)->toBe(1);
});

it('reports an unresolvable base as a target error, never as a clean diff', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');
    $adapter->shouldNotReceive('send');

    $report = diffScanner($adapter)->scanDiff('release');

    expect($report->getTargetError())->toContain('fetch-depth: 0')
        ->and($report->scoreIsMeaningful())->toBeFalse()
        ->and($report->toArray()['overall_score'])->toBeNull();
});

it('reports an empty diff as no changes with a withheld score', function (): void {
    diffRepoGit($this->repo, 'checkout -q main');

    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');

    $report = diffScanner($adapter)->scanDiff('main');

    expect($report->summary)->toStartWith('No changed PHP files found compared to main')
        ->and($report->getTargetError())->toBeNull()
        ->and($report->toArray()['overall_score'])->toBeNull();
});

it('makes no AI request at all in deterministic mode', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');
    $adapter->shouldNotReceive('send');

    $report = diffScanner($adapter, new AccessControlAnalyzer([new FirstFileIdorDetector]))
        ->setDeterministic(true)
        ->scanDiff('main');

    expect($report->totalCount())->toBe(1)
        ->and($report->overallScore)->toBe(80)
        ->and($report->getCoverage()->filesAnalyzed)->toBe(3)
        ->and($report->summary)->toContain('Deterministic scan')
        ->and($report->getUsageTracker()?->totalTokens())->toBe(0);
});

it('never verifies in deterministic mode, even when verification is requested', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');
    $adapter->shouldNotReceive('send');

    $report = diffScanner($adapter, new AccessControlAnalyzer([new FirstFileIdorDetector]))
        ->setDeterministic(true)
        ->setVerify(true)
        ->scanFile('app/Http/Controllers/AlphaController.php');

    expect($report->verificationAttempted)->toBeFalse()
        ->and($report->totalCount())->toBe(1);
});

it('computes the score from asserted findings, not from the AI self-report', function (): void {
    // The AI claims 30/100 but asserts a single Medium finding: the documented
    // penalty-only score is 100 - 10.
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldReceive('sendWithUsage')->andReturn([
        'text' => diffScanAiResponse([[
            'type' => 'sql_injection',
            'severity' => 'medium',
            'location' => 'app/Http/Controllers/AlphaController.php',
            'line' => 9,
            'description' => 'Raw query.',
            'proof' => 'x',
            'fix' => 'y',
        ]], score: 30),
        'usage' => ['prompt_tokens' => 1, 'completion_tokens' => 1],
    ]);

    $report = diffScanner($adapter)->scanFile('app/Http/Controllers/AlphaController.php');

    expect($report->overallScore)->toBe(90);
});

it('says so when the deterministic engine crashes instead of returning a clean report', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');

    $report = diffScanner($adapter, new AccessControlAnalyzer([new CrashingDetector]))
        ->setDeterministic(true)
        ->scanDiff('main');

    expect($report->summary)->toContain('deterministic access-control engine failed')
        ->and($report->getCoverage()->filesAnalyzed)->toBe(0)
        ->and($report->scoreIsMeaningful())->toBeFalse();
});

it('reports a missing path as a target error', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');

    $report = diffScanner($adapter)->scanFile('app/Nope.php');

    expect($report->getTargetError())->toContain('File not found');
});

it('announces the installed package version to MCP clients', function (): void {
    // A #[Version('1.0.0')] attribute survived three releases unchanged.
    expect(HackAuditorMcpServer::packageVersion())->not->toBe('1.0.0')
        ->and(HackAuditorMcpServer::packageVersion())->not->toStartWith('v');
});

it('runs hack:scan --deterministic end to end without touching the AI', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');
    $adapter->shouldNotReceive('send');
    $this->app->instance(AIAdapter::class, $adapter);
    $this->app->forgetInstance(HackScanner::class);

    $exitCode = $this->artisan('hack:scan', ['--deterministic' => true, '--json' => true, '--diff' => true, '--base' => 'main']);

    $exitCode->assertExitCode(0);
});

it('rejects an unresolvable --diff base with exit 2', function (): void {
    $adapter = Mockery::mock(AIAdapter::class);
    $adapter->shouldNotReceive('sendWithUsage');
    $this->app->instance(AIAdapter::class, $adapter);
    $this->app->forgetInstance(HackScanner::class);

    $this->artisan('hack:scan', ['--json' => true, '--diff' => true, '--base' => 'release'])
        ->assertExitCode(2);
});

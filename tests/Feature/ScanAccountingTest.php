<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Report\HtmlReportGenerator;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlDetector;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\ScanCoverage;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageLog;
use Mahdi\HackAuditor\Support\UsageTracker;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * A deterministic detector that always emits one finding.
 *
 * The real-world defect this suite guards was triggered by the deterministic
 * layer adding findings, which rebuilds the report. Using a stub detector keeps
 * the regression pinned to the accounting bug rather than to whatever the real
 * detectors currently decide about a fixture.
 */
final class AlwaysFiringDetector implements AccessControlDetector
{
    public function detect(array $files, AccessControlContext $context): array
    {
        return [
            new Vulnerability(
                type: VulnerabilityType::Idor,
                location: 'app/Http/Controllers/AccountingController.php',
                line: 12,
                severity: SeverityLevel::High,
                description: 'Stub deterministic finding.',
                proof: 'stub',
                fix: 'stub',
            ),
        ];
    }
}

function accountingAiResponse(int $score = 100): string
{
    return json_encode([
        'vulnerabilities' => [],
        'overall_score' => $score,
        'summary' => 'No issues found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

function accountingAdapter(string $response, int $promptTokens = 12_000, int $completionTokens = 3_000): AIAdapter
{
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('send')->andReturn($response);
    $mock->shouldReceive('sendWithUsage')->andReturn([
        'text' => $response,
        'usage' => [
            'prompt_tokens' => $promptTokens,
            'completion_tokens' => $completionTokens,
        ],
    ]);

    return $mock;
}

function accountingScanner(AIAdapter $adapter, ?AccessControlAnalyzer $analyzer = null): HackScanner
{
    return new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $adapter,
        accessControlAnalyzer: $analyzer ?? new AccessControlAnalyzer([]),
    );
}

function writeAccountingController(string $directory, string $name): void
{
    file_put_contents(
        $directory.'/'.$name,
        '<?php'."\n".'namespace App\Http\Controllers;'."\n"
        .'class '.basename($name, '.php').' { public function index() { return []; } }'."\n",
    );
}

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-accounting-'.uniqid();
    mkdir($this->tempDir.'/app/Http/Controllers', 0755, true);
    $this->tempDir = realpath($this->tempDir);

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);
    $this->app->useStoragePath($this->tempDir.'/storage');
    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
});

afterEach(function (): void {
    if (! is_dir($this->tempDir)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $file) {
        $file->isDir() ? rmdir($file->getRealPath()) : unlink($file->getRealPath());
    }

    rmdir($this->tempDir);
});

/*
|--------------------------------------------------------------------------
| 1. Untracked spend
|--------------------------------------------------------------------------
*/

it('keeps token accounting when the deterministic layer rebuilds the report', function (): void {
    // The real 73-file, 213-second, $3-5 scan recorded ZERO tokens. Cause: the
    // full-scan path attached the UsageTracker inside scanChunks(), and the
    // deterministic access-control merge that ran afterwards constructed a
    // brand-new VulnerabilityReport, silently dropping the tracker. Any scan
    // where the deterministic layer produced a finding therefore lost its
    // entire spend record, which is exactly what a real codebase does.
    writeAccountingController($this->tempDir.'/app/Http/Controllers', 'AccountingController.php');

    $scanner = accountingScanner(
        accountingAdapter(accountingAiResponse()),
        new AccessControlAnalyzer([new AlwaysFiringDetector]),
    );

    $tracker = new UsageTracker;
    $scanner->setUsageTracker($tracker);

    $report = $scanner->scan();

    expect($report->totalCount())->toBe(1)
        ->and($report->getUsageTracker())->not->toBeNull()
        ->and($report->hasUsageData())->toBeTrue()
        ->and($report->getUsageTracker()->totalTokens())->toBe(15_000)
        ->and($report->toArray())->toHaveKey('usage')
        ->and($report->toArray()['usage']['total_tokens'])->toBe(15_000);
});

it('keeps token accounting on the plain full-scan path', function (): void {
    writeAccountingController($this->tempDir.'/app/Http/Controllers', 'AccountingController.php');

    $scanner = accountingScanner(accountingAdapter(accountingAiResponse()));

    $tracker = new UsageTracker;
    $scanner->setUsageTracker($tracker);

    $report = $scanner->scan();

    expect($report->hasUsageData())->toBeTrue()
        ->and($report->getUsageTracker()->totalTokens())->toBe(15_000)
        ->and($report->getUsageTracker()->getRequests())->toBe(1);
});

it('records tokens for a chunk whose AI response could not be parsed', function (): void {
    // Spend on a request whose response is garbage is still spend. It must be
    // billed to the user's budget, not written off because the parse failed.
    writeAccountingController($this->tempDir.'/app/Http/Controllers', 'AccountingController.php');

    $scanner = accountingScanner(accountingAdapter('not json at all'));

    $tracker = new UsageTracker;
    $scanner->setUsageTracker($tracker);

    $report = $scanner->scan();

    expect($report->getUsageTracker()->totalTokens())->toBe(15_000)
        ->and($report->hasUsageData())->toBeTrue();
});

it('writes the full-scan spend to the usage log so hack:usage can see it', function (): void {
    // hack:usage showed only two small scans after the expensive run. The main
    // scan path never reached the usage log at all, so --limit budgeting could
    // not cover it. This is the end-to-end guard on that.
    writeAccountingController($this->tempDir.'/app/Http/Controllers', 'AccountingController.php');

    $this->app->instance(AIAdapter::class, accountingAdapter(accountingAiResponse()));

    $this->artisan('hack:scan', ['--json' => true, '--force' => true])->assertSuccessful();

    $entries = (new UsageLog)->all();

    expect($entries)->toHaveCount(1)
        ->and($entries[0]['total_tokens'])->toBe(15_000)
        ->and($entries[0]['estimated_cost_usd'])->toBeGreaterThan(0.0)
        ->and($entries[0]['files_scanned'])->toBe(1)
        ->and($entries[0]['coverage_complete'])->toBeTrue();
});

it('logs the spend of a run that only partly succeeded, with coverage marked incomplete', function (): void {
    // Spend on a chunk that blew up is still spend, and the log entry must say
    // the run did not cover everything so the cost cannot be attributed to a
    // clean bill of health.
    $this->app['config']->set('hack-auditor.scan.chunk_size', 1);

    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'AlphaController.php');
    writeAccountingController($controllers, 'BetaController.php');

    $call = 0;
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')->andReturnUsing(function () use (&$call): array {
        $call++;

        return [
            'text' => $call === 1 ? accountingAiResponse() : 'not json',
            'usage' => ['prompt_tokens' => 7_000, 'completion_tokens' => 500],
        ];
    });
    $mock->shouldReceive('send')->andReturn(accountingAiResponse());
    $this->app->instance(AIAdapter::class, $mock);

    $this->artisan('hack:scan', ['--json' => true, '--force' => true])->assertSuccessful();

    $entries = (new UsageLog)->all();

    expect($entries)->toHaveCount(1)
        ->and($entries[0]['total_tokens'])->toBe(15_000)
        ->and($entries[0]['files_scanned'])->toBe(1)
        ->and($entries[0]['files_skipped'])->toBe(1)
        ->and($entries[0]['coverage_complete'])->toBeFalse()
        ->and($entries[0]['score'])->toBeNull();
});

it('carries usage, coverage and skip count onto a rebuilt report', function (): void {
    $original = new VulnerabilityReport([], 100, 'original', '');
    $tracker = new UsageTracker;
    $tracker->record(1_000, 500);
    $original->setUsageTracker($tracker);
    $original->setCoverage(new ScanCoverage(
        filesDiscovered: 4,
        filesAnalyzed: 3,
        skipped: [['path' => 'a.php', 'reason' => ScanCoverage::REASON_AI_FAILURE]],
    ));

    $rebuilt = (new VulnerabilityReport([], 40, 'rebuilt', ''))->inheritScanStateFrom($original);

    expect($rebuilt->getUsageTracker())->toBe($tracker)
        ->and($rebuilt->hasUsageData())->toBeTrue()
        ->and($rebuilt->getFilesSkipped())->toBe(1)
        ->and($rebuilt->getCoverage()?->filesAnalyzed)->toBe(3);
});

/*
|--------------------------------------------------------------------------
| 2. Silent partial coverage
|--------------------------------------------------------------------------
*/

it('names every file that went unanalyzed after an AI failure', function (): void {
    // The real run printed "1 chunk(s) returned unparseable AI responses and
    // were skipped" and then a definitive score. Which files? Unknowable.
    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'AlphaController.php');
    writeAccountingController($controllers, 'BetaController.php');

    $scanner = accountingScanner(accountingAdapter('}{ not json'));

    $scanner->setUsageTracker(new UsageTracker);

    $report = $scanner->scan();
    $coverage = $report->getCoverage();

    expect($coverage)->not->toBeNull()
        ->and($coverage->filesDiscovered)->toBe(2)
        ->and($coverage->filesAnalyzed)->toBe(0)
        ->and($coverage->isComplete())->toBeFalse()
        ->and($coverage->skippedPaths())->toContain('app/Http/Controllers/AlphaController.php')
        ->and($coverage->skippedPaths())->toContain('app/Http/Controllers/BetaController.php')
        ->and($coverage->skippedByReason())->toHaveKey(ScanCoverage::REASON_AI_FAILURE);
});

it('names every file skipped because the token budget ran out', function (): void {
    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'BudgetController.php');

    $scanner = accountingScanner(accountingAdapter(accountingAiResponse()));

    $tracker = new UsageTracker(5_000);
    $tracker->record(4_900, 0);
    $scanner->setUsageTracker($tracker);

    $coverage = $scanner->scan()->getCoverage();

    expect($coverage->filesAnalyzed)->toBe(0)
        ->and($coverage->skippedPaths())->toBe(['app/Http/Controllers/BudgetController.php'])
        ->and($coverage->skippedByReason())->toHaveKey(ScanCoverage::REASON_TOKEN_LIMIT);
});

it('exposes coverage and the skipped file list in the report array', function (): void {
    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'AlphaController.php');

    $scanner = accountingScanner(accountingAdapter('not json'));
    $scanner->setUsageTracker(new UsageTracker);

    $data = $scanner->scan()->toArray();

    expect($data)->toHaveKey('coverage')
        ->and($data['coverage']['complete'])->toBeFalse()
        ->and($data['coverage']['files_analyzed'])->toBe(0)
        ->and($data['coverage']['skipped_files'][0]['path'])->toBe('app/Http/Controllers/AlphaController.php')
        ->and($data['coverage']['skipped_files'][0]['reason'])->toBe(ScanCoverage::REASON_AI_FAILURE)
        ->and($data['coverage']['skipped_files'][0]['reason_label'])->not->toBe('');
});

it('names the skipped files in the console output instead of only counting them', function (): void {
    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'PaymentsController.php');

    $this->app->instance(AIAdapter::class, accountingAdapter('not json'));

    $this->artisan('hack:scan', ['--force' => true])
        ->expectsOutputToContain('INCOMPLETE')
        ->expectsOutputToContain('app/Http/Controllers/PaymentsController.php')
        ->assertSuccessful();
});

/*
|--------------------------------------------------------------------------
| 3. Meaningless score
|--------------------------------------------------------------------------
*/

it('refuses to score a scan that analyzed nothing', function (): void {
    // Scanning an EMPTY directory used to score a flawless 100/100 — the
    // penalty-only score rewards scanning nothing.
    $scanner = accountingScanner(accountingAdapter(accountingAiResponse()));
    $scanner->setUsageTracker(new UsageTracker);

    $report = $scanner->scan();
    $data = $report->toArray();

    expect($report->scoreIsMeaningful())->toBeFalse()
        ->and($report->scoreSuppressionReason())->not->toBeNull()
        ->and($data['overall_score'])->toBeNull()
        ->and($data['score_suppressed'])->toBeTrue()
        ->and($data['coverage']['files_discovered'])->toBe(0);
});

it('does not print 100/100 for an empty scan', function (): void {
    $this->app->instance(AIAdapter::class, accountingAdapter(accountingAiResponse()));

    $this->artisan('hack:scan', ['--force' => true])
        ->doesntExpectOutputToContain('100/100')
        ->expectsOutputToContain('not available')
        ->assertSuccessful();
});

it('suppresses the score when some files were analyzed and some were not', function (): void {
    // The dangerous case: the scan succeeded on most files, so the report LOOKS
    // authoritative, but part of the codebase was never examined. The number is
    // withheld rather than presented over partial evidence.
    $this->app['config']->set('hack-auditor.scan.chunk_size', 1);

    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'AlphaController.php');
    writeAccountingController($controllers, 'BetaController.php');

    $call = 0;
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')->andReturnUsing(function () use (&$call): array {
        $call++;

        return [
            'text' => $call === 1 ? accountingAiResponse(score: 90) : 'not json',
            'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 10],
        ];
    });
    $mock->shouldReceive('send')->andReturn(accountingAiResponse());

    $scanner = accountingScanner($mock);
    $scanner->setUsageTracker(new UsageTracker);

    $report = $scanner->scan();
    $coverage = $report->getCoverage();

    expect($coverage->filesDiscovered)->toBe(2)
        ->and($coverage->filesAnalyzed)->toBe(1)
        ->and($coverage->skippedPaths())->toBe(['app/Http/Controllers/BetaController.php'])
        ->and($report->scoreIsMeaningful())->toBeFalse()
        ->and($report->scoreSuppressionReason())->toContain('1 of 2')
        ->and($report->toArray()['overall_score'])->toBeNull();
});

it('keeps the score when every discovered file was analyzed', function (): void {
    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'AlphaController.php');

    $scanner = accountingScanner(accountingAdapter(accountingAiResponse(score: 88)));
    $scanner->setUsageTracker(new UsageTracker);

    $report = $scanner->scan();

    expect($report->scoreIsMeaningful())->toBeTrue()
        ->and($report->scoreSuppressionReason())->toBeNull()
        ->and($report->toArray()['overall_score'])->toBe(88)
        ->and($report->getCoverage()->isComplete())->toBeTrue();
});

/*
|--------------------------------------------------------------------------
| 4. --path=<directory>
|--------------------------------------------------------------------------
*/

it('scans every file under a --path directory instead of reading the directory as a file', function (): void {
    // `--path` has always advertised "a specific file or directory". A directory
    // used to satisfy file_exists(), extract to EMPTY content, and produce a
    // full-price AI request over nothing plus a confident, evidence-free report.
    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'AlphaController.php');
    writeAccountingController($controllers, 'BetaController.php');

    $seen = [];
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('sendWithUsage')
        ->andReturnUsing(function (string $system, string $user) use (&$seen): array {
            $seen[] = $user;

            return [
                'text' => accountingAiResponse(),
                'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 10],
            ];
        });
    $mock->shouldReceive('send')->andReturn(accountingAiResponse());

    $scanner = accountingScanner($mock);
    $scanner->setUsageTracker(new UsageTracker);

    $report = $scanner->scanFile('app/Http/Controllers');
    $prompt = implode("\n", $seen);

    expect($report->getCoverage()->filesDiscovered)->toBe(2)
        ->and($report->getCoverage()->filesAnalyzed)->toBe(2)
        ->and($report->getCoverage()->isComplete())->toBeTrue()
        ->and($report->summary)->not->toContain('File not found')
        ->and($prompt)->toContain('AlphaController.php')
        ->and($prompt)->toContain('BetaController.php');
});

it('reports honestly when a --path directory holds no scannable files', function (): void {
    mkdir($this->tempDir.'/app/Empty', 0755, true);

    $scanner = accountingScanner(accountingAdapter(accountingAiResponse()));
    $scanner->setUsageTracker(new UsageTracker);

    $report = $scanner->scanFile('app/Empty');

    expect($report->summary)->toContain('No scannable files found')
        ->and($report->scoreIsMeaningful())->toBeFalse();
});

it('never reaches sensitive files through a --path directory', function (): void {
    $secrets = $this->tempDir.'/app/Secrets';
    mkdir($secrets, 0755, true);
    file_put_contents($secrets.'/private.key', 'secret-material');
    file_put_contents($secrets.'/.env.backup', 'DB_PASSWORD=hunter2');

    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldNotReceive('send');
    $mock->shouldNotReceive('sendWithUsage');

    $scanner = accountingScanner($mock);
    $scanner->setUsageTracker(new UsageTracker);

    $report = $scanner->scanFile('app/Secrets');

    expect($report->getCoverage()->filesDiscovered)->toBe(0)
        ->and($report->summary)->toContain('No scannable files found');
});

/*
|--------------------------------------------------------------------------
| Downstream surfaces
|--------------------------------------------------------------------------
*/

it('withholds the score and names skipped files in the HTML report', function (): void {
    $report = new VulnerabilityReport([], 100, 'Nothing found.', '');
    $report->setCoverage(new ScanCoverage(
        filesDiscovered: 3,
        filesAnalyzed: 1,
        skipped: [
            ['path' => 'app/Http/Controllers/PaymentsController.php', 'reason' => ScanCoverage::REASON_AI_FAILURE],
            ['path' => 'app/Http/Controllers/AdminController.php', 'reason' => ScanCoverage::REASON_TOKEN_LIMIT],
        ],
    ));

    $html = app(HtmlReportGenerator::class)->generate($report);

    expect($html)->toContain('Incomplete scan')
        ->and($html)->toContain('app/Http/Controllers/PaymentsController.php')
        ->and($html)->toContain('app/Http/Controllers/AdminController.php')
        ->and($html)->toContain('>n/a<')
        ->and($html)->not->toContain('>100<');
});

it('keeps the numeric score in the HTML report when coverage is complete', function (): void {
    $report = new VulnerabilityReport([], 72, 'All good.', '');
    $report->setCoverage(ScanCoverage::complete(4));

    $html = app(HtmlReportGenerator::class)->generate($report);

    expect($html)->toContain('>72<')
        ->and($html)->not->toContain('Incomplete scan');
});

it('collectFrom applies the same filters as a configured scan', function (): void {
    $controllers = $this->tempDir.'/app/Http/Controllers';
    writeAccountingController($controllers, 'AlphaController.php');
    file_put_contents($controllers.'/notes.txt', 'not php');
    file_put_contents($controllers.'/service.key', 'secret');

    $collected = app(FileCollector::class)->collectFrom($controllers);

    expect($collected)->toHaveCount(1)
        ->and(basename($collected->first()->getRealPath()))->toBe('AlphaController.php');
});

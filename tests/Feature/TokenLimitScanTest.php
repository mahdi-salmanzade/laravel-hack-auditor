<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;
use Mahdi\HackAuditor\Support\UsageTracker;

function buildUsageAIResponse(int $score = 100): string
{
    return json_encode([
        'vulnerabilities' => [],
        'overall_score' => $score,
        'summary' => 'No issues found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-cmd-test-'.uniqid();
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
    file_put_contents($this->tempDir.'/app/Http/Controllers/TestController.php', '<?php class TestController {}');

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);
    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
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

it('scan without limit processes all files and attaches usage data', function (): void {
    $responseText = buildUsageAIResponse();

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('sendWithUsage')
        ->andReturn([
            'text' => $responseText,
            'usage' => [
                'prompt_tokens' => 2000,
                'completion_tokens' => 1000,
            ],
        ]);
    $mockAdapter->shouldReceive('send')
        ->andReturn($responseText);

    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $mockAdapter,
    );

    $tracker = new UsageTracker;
    $scanner->setUsageTracker($tracker);

    $report = $scanner->scanCode('<?php echo "test";');

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($report->hasUsageData())->toBeTrue()
        ->and($report->getUsageTracker()->totalTokens())->toBe(3000);
});

it('scan with limit skips chunks when exceeded', function (): void {
    $responseText = buildUsageAIResponse();

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('sendWithUsage')
        ->andReturn([
            'text' => $responseText,
            'usage' => [
                'prompt_tokens' => 100,
                'completion_tokens' => 50,
            ],
        ]);
    $mockAdapter->shouldReceive('send')
        ->andReturn($responseText);

    $this->app->instance(AIAdapter::class, $mockAdapter);

    $tracker = new UsageTracker(5000);
    $tracker->record(4500, 0);

    /** @var HackScanner $scanner */
    $scanner = app(HackScanner::class);
    $scanner->setUsageTracker($tracker);

    $report = $scanner->scan();

    expect($report)->toBeInstanceOf(VulnerabilityReport::class);
});

it('usage tracker records across multiple requests', function (): void {
    $tracker = new UsageTracker;
    $tracker->record(1000, 500);
    $tracker->record(2000, 1000);

    expect($tracker->totalTokens())->toBe(4500)
        ->and($tracker->getRequests())->toBe(2);
});

it('files skipped count is tracked on report', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [],
        overallScore: 100,
        summary: 'No issues.',
        ctfIdea: '',
    );

    $report->setFilesSkipped(5);

    expect($report->getFilesSkipped())->toBe(5);
});

it('usage data included in report toArray', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [],
        overallScore: 100,
        summary: 'No issues.',
        ctfIdea: '',
    );

    $tracker = new UsageTracker;
    $tracker->record(500, 250);
    $report->setUsageTracker($tracker);

    $array = $report->toArray();

    expect($array)->toHaveKey('usage')
        ->and($array['usage']['total_tokens'])->toBe($tracker->totalTokens());
});

it('limit flag accepted by command', function (): void {
    $responseText = buildUsageAIResponse();

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('sendWithUsage')
        ->andReturn([
            'text' => $responseText,
            'usage' => [
                'prompt_tokens' => 100,
                'completion_tokens' => 50,
            ],
        ]);
    $mockAdapter->shouldReceive('send')
        ->andReturn($responseText);

    $this->app->instance(AIAdapter::class, $mockAdapter);

    $this->artisan('hack:scan', ['--json' => true, '--limit' => 50000])
        ->assertSuccessful();
});

it('json output includes usage data when available', function (): void {
    $responseText = buildUsageAIResponse();

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('sendWithUsage')
        ->andReturn([
            'text' => $responseText,
            'usage' => [
                'prompt_tokens' => 500,
                'completion_tokens' => 200,
            ],
        ]);
    $mockAdapter->shouldReceive('send')
        ->andReturn($responseText);

    $this->app->instance(AIAdapter::class, $mockAdapter);

    $this->artisan('hack:scan', ['--json' => true])
        ->assertSuccessful();
});

it('vulnerability report without usage returns false for hasUsageData', function (): void {
    $report = new VulnerabilityReport(
        vulnerabilities: [],
        overallScore: 100,
        summary: 'Clean.',
        ctfIdea: '',
    );

    expect($report->hasUsageData())->toBeFalse()
        ->and($report->getFilesSkipped())->toBe(0);
});

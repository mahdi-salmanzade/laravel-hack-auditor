<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlDetector;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\Vulnerability;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\UsageTracker;
use Mahdi\HackAuditor\Support\VulnerabilityType;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * A detector that emits one CRITICAL question.
 *
 * The severity is deliberately the worst available: if class gating works, the
 * single most alarming-looking finding the tool can produce still cannot move
 * the score or fail a build, because nobody proved it.
 */
final class CriticalQuestionDetector implements AccessControlDetector
{
    public function detect(array $files, AccessControlContext $context): array
    {
        return [
            new Vulnerability(
                type: VulnerabilityType::Idor,
                location: 'app/Http/Controllers/GatingController.php',
                line: 12,
                severity: SeverityLevel::Critical,
                description: 'Is access to this record enforced somewhere this scan cannot read?',
                proof: 'Contract::findOrFail($id)',
                fix: "add \$this->authorize('delete', \$contract) in destroy()",
                findingClass: FindingClass::Review,
                confidence: Confidence::Possible,
            ),
        ];
    }
}

/**
 * The same finding, asserted rather than asked. Guards that gating did not
 * simply switch the penalty off for everyone.
 */
final class CriticalAssertionDetector implements AccessControlDetector
{
    public function detect(array $files, AccessControlContext $context): array
    {
        return [
            new Vulnerability(
                type: VulnerabilityType::Idor,
                location: 'app/Http/Controllers/GatingController.php',
                line: 12,
                severity: SeverityLevel::Critical,
                description: 'Attacker-controlled id reaches findOrFail() with no ownership scope.',
                proof: 'Contract::findOrFail($request->id)',
                fix: 'Scope the query to the authenticated user.',
                findingClass: FindingClass::Vulnerability,
                confidence: Confidence::Proven,
            ),
        ];
    }
}

function gatingAiResponse(int $score = 90): string
{
    return json_encode([
        'vulnerabilities' => [],
        'overall_score' => $score,
        'summary' => 'No issues found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

function gatingAdapter(): AIAdapter
{
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('send')->andReturn(gatingAiResponse());
    $mock->shouldReceive('sendWithUsage')->andReturn([
        'text' => gatingAiResponse(),
        'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 10],
    ]);

    return $mock;
}

function gatingScanner(AccessControlDetector $detector): HackScanner
{
    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: gatingAdapter(),
        accessControlAnalyzer: new AccessControlAnalyzer([$detector]),
    );

    $scanner->setUsageTracker(new UsageTracker);

    return $scanner;
}

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-gating-'.uniqid();
    mkdir($this->tempDir.'/app/Http/Controllers', 0755, true);
    $this->tempDir = realpath($this->tempDir);

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);
    $this->app->useStoragePath($this->tempDir.'/storage');
    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);

    file_put_contents(
        $this->tempDir.'/app/Http/Controllers/GatingController.php',
        '<?php'."\n".'namespace App\Http\Controllers;'."\n"
        .'class GatingController { public function index() { return []; } }'."\n",
    );
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

it('does not let a critical review item touch the score', function (): void {
    $report = gatingScanner(new CriticalQuestionDetector)->scan();

    expect($report->overallScore)->toBe(90)
        ->and($report->scoreIsMeaningful())->toBeTrue()
        ->and($report->totalCount())->toBe(0)
        ->and($report->reviewCount())->toBe(1)
        ->and($report->hasCritical())->toBeFalse();
});

it('still penalises the score for an asserted critical vulnerability', function (): void {
    // The mirror image: gating must suppress questions, not penalties.
    $report = gatingScanner(new CriticalAssertionDetector)->scan();

    expect($report->overallScore)->toBe(50)
        ->and($report->totalCount())->toBe(1)
        ->and($report->reviewCount())->toBe(0)
        ->and($report->hasCritical())->toBeTrue();
});

it('exits successfully when the only critical finding is a question', function (): void {
    $this->app->instance(HackScanner::class, gatingScanner(new CriticalQuestionDetector));

    $this->artisan('hack:scan', ['--force' => true])
        ->assertSuccessful();
});

it('fails the build for an asserted critical vulnerability', function (): void {
    $this->app->instance(HackScanner::class, gatingScanner(new CriticalAssertionDetector));

    $this->artisan('hack:scan', ['--force' => true])
        ->assertFailed();
});

it('prints the two sections, with the review section marked as questions', function (): void {
    $this->app->instance(HackScanner::class, gatingScanner(new CriticalQuestionDetector));

    $this->artisan('hack:scan', ['--force' => true])
        ->expectsOutputToContain('Confirmed vulnerabilities (0)')
        ->expectsOutputToContain('No confirmed vulnerabilities.')
        ->expectsOutputToContain('Needs review (1)')
        ->expectsOutputToContain('NOT vulnerabilities')
        ->assertSuccessful();
});

it('never prints a fix for a review item, even with --fix', function (): void {
    $this->app->instance(HackScanner::class, gatingScanner(new CriticalQuestionDetector));

    $this->artisan('hack:scan', ['--force' => true, '--fix' => true])
        ->doesntExpectOutputToContain("authorize('delete'")
        ->doesntExpectOutputToContain('Suggested Fixes')
        ->assertSuccessful();
});

it('states coverage rather than safety when nothing was confirmed', function (): void {
    $this->app->instance(HackScanner::class, gatingScanner(new CriticalQuestionDetector));

    $this->artisan('hack:scan', ['--force' => true])
        ->expectsOutputToContain('All 1 discovered file(s) were analysed')
        ->assertSuccessful();
});

it('keeps the classes apart in --json output', function (): void {
    // The whole JSON document arrives as a single write, so it is captured and
    // decoded rather than asserted one substring at a time.
    $this->app->instance(HackScanner::class, gatingScanner(new CriticalQuestionDetector));

    $output = new BufferedOutput;
    $exitCode = $this->app->make(Kernel::class)->call(
        'hack:scan',
        ['--force' => true, '--json' => true],
        $output,
    );

    /** @var array<string, mixed> $json */
    $json = json_decode($output->fetch(), true, 512, JSON_THROW_ON_ERROR);

    expect($exitCode)->toBe(0)
        ->and($json['vulnerabilities'])->toBeEmpty()
        ->and($json['review_items'])->toHaveCount(1)
        ->and($json['review_items'][0]['class'])->toBe('review')
        ->and($json['review_items'][0]['confidence'])->toBe('possible')
        ->and($json['review_items'][0]['fix'])->toBe('')
        ->and($json['counts']['total'])->toBe(0)
        ->and($json['counts']['critical'])->toBe(0)
        ->and($json['counts']['review'])->toBe(1)
        ->and($json['overall_score'])->toBe(90);
});

<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\Benchmark\BenchmarkRunner;
use Mahdi\HackAuditor\Benchmark\CorpusRoutes;
use Mahdi\HackAuditor\Benchmark\CorpusSamples;
use Mahdi\HackAuditor\Benchmark\GroundTruth;
use Mahdi\HackAuditor\Console\HackBenchmarkCommand;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\Vulnerability;

/**
 * THE ACCURACY GATE MUST MEASURE THE CORPUS IT CLAIMS TO MEASURE.
 *
 * The failure these tests exist to catch is not "a detector got worse". It is
 * "a sample stopped being analysed at all, and the gate kept printing a score".
 *
 * That is what happened: the access-control engine learned to refuse findings it
 * cannot attribute to a routed entry point — the rule that took 191 false IDOR
 * reports on 6,221 real files down to zero — and the benchmark corpus, being a
 * directory of standalone fixture files with no application around them, had no
 * route table at all. Every sample resolved to 'unreachable' and was dropped
 * before analysis. The planted IDOR at IdorController.php:14 stopped being
 * credited and not one test went red.
 *
 * The corpus now ships its own route manifest (tests/Fixtures/benchmark/routes.php)
 * so it describes the application it is. These tests fail the moment a sample
 * becomes unanalysable again — unparsable, unrouted, or simply absent from the
 * ground truth.
 *
 * NOTE ON SCOPE: this corpus is synthetic and was authored alongside the
 * detectors. It measures RECALL. It says nothing about precision on real code.
 */
beforeEach(function (): void {
    $this->app[Kernel::class]->registerCommand(
        $this->app->make(HackBenchmarkCommand::class),
    );
});

/**
 * Render findings so a failure message names the file, line and claim.
 *
 * @param  array<int, Vulnerability>  $findings
 * @return array<int, string>
 */
function corpusDescribe(array $findings): array
{
    return array_map(
        static fn (Vulnerability $v): string => sprintf('%s:%d [%s]', $v->location, $v->line, $v->type->value),
        $findings,
    );
}

/**
 * Run the deterministic engine over the corpus with a given context.
 *
 * @return array<int, Vulnerability>
 */
function corpusFindings(AccessControlContext $context): array
{
    return (new AccessControlAnalyzer)->analyze(CorpusSamples::default()->files, $context);
}

it('parses every sample in the corpus', function (): void {
    // An unparsable sample is discarded by the AST layer before any detector
    // runs, which silently shrinks the corpus the score is computed over.
    expect(CorpusSamples::default()->unparsableFiles())->toBe([]);
});

it('routes every controller action in the corpus', function (): void {
    // THE REGRESSION GUARD. A controller action with no route entry resolves to
    // 'unreachable' and is dropped before the access-control engine sees it, so
    // the gate would report a score for a sample it never analysed. Adding a
    // controller sample without adding its route must fail here, loudly.
    $samples = CorpusSamples::default();
    $unrouted = $samples->unroutedActions(CorpusRoutes::default());

    expect($unrouted)->toBe([], 'Add these to tests/Fixtures/benchmark/routes.php — an unrouted sample is unmeasured, not clean.');

    // And the corpus is not empty, so the assertion above cannot pass vacuously.
    expect($samples->controllerActions())->not->toBeEmpty();
});

it('keeps the ground truth and the samples directory in step', function (): void {
    $onDisk = array_map(
        static fn (array $file): string => $file['path'],
        CorpusSamples::default()->files,
    );

    $labeled = GroundTruth::default()->files();

    sort($onDisk);
    sort($labeled);

    expect($labeled)->toBe($onDisk);
});

it('credits the planted IDOR at its ground-truth line', function (): void {
    // The specific finding the broken gate lost: IdorController.php:14,
    // Invoice::findOrFail($id) returned straight to the caller.
    $findings = corpusFindings(CorpusRoutes::default()->context());

    expect(corpusDescribe($findings))->toContain('IdorController.php:14 [idor]');
});

it('scores the planted IDOR as a true positive', function (): void {
    $groundTruth = GroundTruth::default()->onlyEngine(GroundTruth::ENGINE_DETERMINISTIC);
    $result = (new BenchmarkRunner($groundTruth))->score(corpusFindings(CorpusRoutes::default()->context()));

    expect($result['matches'])->toContain(['file' => 'IdorController.php', 'type' => 'idor', 'line' => 14])
        ->and($result['missed_labels'])->not->toContain(['file' => 'IdorController.php', 'type' => 'idor', 'line' => 14]);
});

it('owes that credit to the route manifest, not to a relaxed detector', function (): void {
    // The counter-example that keeps this honest. With no route table the engine
    // must still refuse to name an entry point it cannot see — that refusal is
    // the precision win. The manifest is what supplies the missing application,
    // and nothing about the detector was loosened to make the corpus score.
    $findings = corpusFindings(new AccessControlContext);

    expect(corpusDescribe($findings))->not->toContain('IdorController.php:14 [idor]');
});

it('refuses to report a score for a corpus it cannot analyse', function (): void {
    $manifest = sys_get_temp_dir().'/hack-auditor-empty-routes-'.getmypid().'.php';
    file_put_contents($manifest, "<?php\n\nreturn ['routes' => []];\n");

    try {
        $code = Artisan::call('hack:benchmark', ['--deterministic' => true, '--routes' => $manifest]);
        $output = Artisan::output();
    } finally {
        @unlink($manifest);
    }

    expect($code)->toBe(1)
        ->and($output)->toContain('no route in the manifest')
        ->and($output)->toContain('IdorController@show')
        ->and($output)->not->toContain('F1 Score');
});

it('runs the deterministic gate with no AI provider at all', function (): void {
    // No AIAdapter is bound to anything here: the reproducible engine must be
    // gateable on every commit without a key, which is the only way this stays
    // a gate rather than a thing someone runs occasionally.
    $code = Artisan::call('hack:benchmark', ['--deterministic' => true, '--json' => true]);
    $output = Artisan::output();

    /** @var array<string, mixed> $payload */
    $payload = json_decode($output, true, 512, JSON_THROW_ON_ERROR);

    expect($code)->toBe(0)
        ->and($payload['scope'])->toBe('deterministic')
        ->and($payload['matches'])->toContain(['file' => 'IdorController.php', 'type' => 'idor', 'line' => 14]);
});

it('lets the deterministic engine reach the corpus through the full pipeline', function (): void {
    // End-to-end proof that the corpus route manifest reaches the real scanner:
    // the AI finds NOTHING, so every credited finding here came from the
    // deterministic engine running against a corpus it could actually reach.
    $adapter = Mockery::mock(AIAdapter::class);
    $empty = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 100,
        'summary' => 'no AI findings',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
    $adapter->shouldReceive('send')->andReturn($empty);
    $adapter->shouldReceive('sendWithUsage')->andReturn(['text' => $empty, 'usage' => []]);

    $this->app->instance(AIAdapter::class, $adapter);

    Artisan::call('hack:benchmark', ['--json' => true]);

    /** @var array<string, mixed> $payload */
    $payload = json_decode(Artisan::output(), true, 512, JSON_THROW_ON_ERROR);

    expect($payload['scope'])->toBe('full')
        ->and($payload['matches'])->toContain(['file' => 'IdorController.php', 'type' => 'idor', 'line' => 14]);
});

it('leaves the host route table exactly as it found it', function (): void {
    $this->app->instance(AIAdapter::class, Mockery::mock(AIAdapter::class)
        ->shouldReceive('send')->andReturn('{"vulnerabilities":[],"overall_score":100,"summary":"","ctf_idea":""}')
        ->shouldReceive('sendWithUsage')->andReturn(['text' => '{"vulnerabilities":[],"overall_score":100,"summary":"","ctf_idea":""}', 'usage' => []])
        ->getMock());

    $router = $this->app['router'];
    $before = count($router->getRoutes()->getRoutes());

    Artisan::call('hack:benchmark', ['--json' => true]);

    expect(count($router->getRoutes()->getRoutes()))->toBe($before);
});

it('states the synthetic-corpus caveat in its own output', function (): void {
    // A number copied out of a terminal has to carry its own scope with it.
    Artisan::call('hack:benchmark', ['--deterministic' => true]);

    expect(Artisan::output())
        ->toContain('SYNTHETIC')
        ->toContain('recall check')
        ->toContain('not a precision claim about real code');
});

it('tags every ground-truth label with the engine responsible for it', function (): void {
    // An untagged label silently defaults to 'ai' and drops out of the
    // deterministic gate. Force the choice to be made in the fixture.
    /** @var array<string, mixed> $raw */
    $raw = json_decode((string) file_get_contents(GroundTruth::defaultPath()), true, 512, JSON_THROW_ON_ERROR);

    $untagged = [];

    /** @var array<int, array<string, mixed>> $samples */
    $samples = $raw['samples'];

    foreach ($samples as $sample) {
        /** @var array<int, array<string, mixed>> $expected */
        $expected = $sample['expected'];

        foreach ($expected as $entry) {
            if (! in_array($entry['engine'] ?? null, [GroundTruth::ENGINE_DETERMINISTIC, GroundTruth::ENGINE_AI], true)) {
                $untagged[] = $sample['file'].':'.($entry['line'] ?? '?');
            }
        }
    }

    expect($untagged)->toBe([]);
});

it('scopes the deterministic gate to a real subset of the corpus', function (): void {
    $full = GroundTruth::default();
    $deterministic = $full->onlyEngine(GroundTruth::ENGINE_DETERMINISTIC);

    // Every sample file survives the filter — dropping a file would drop it from
    // the corpus, and findings outside the corpus are ignored rather than
    // counted, which would quietly stop penalising false positives there.
    expect($deterministic->files())->toBe($full->files())
        ->and($deterministic->expectedVulnerabilityCount())->toBeGreaterThan(0)
        ->and($deterministic->expectedVulnerabilityCount())->toBeLessThan($full->expectedVulnerabilityCount())
        ->and($full->labelsExcludedFrom(GroundTruth::ENGINE_DETERMINISTIC))->not->toBeEmpty();
});

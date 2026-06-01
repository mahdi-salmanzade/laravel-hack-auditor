<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\AccessControl\SsrfDetector;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 */
function runSsrfDetector(array $files): array
{
    $detector = new SsrfDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, new AccessControlContext);
}

function ssrfController(string $methods): array
{
    return [[
        'path' => 'app/Http/Controllers/FetchController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Http;\nclass FetchController\n{\n{$methods}\n}\n",
    ]];
}

it('flags Http::get with a url from request input via local variable', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            $url = $request->input('url');
            $response = Http::get($url);
            return response($response->body());
        }
    PHP;

    $findings = runSsrfDetector(ssrfController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Ssrf)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->line)->toBeGreaterThan(1)
        ->and($findings[0]->description)->toContain('fetch');
});

it('flags Http::get with inline request input', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            return Http::get($request->input('url'))->body();
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toHaveCount(1);
});

it('flags a chained Http::withToken()->get() to a user url', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            $url = $request->input('url');
            return Http::withToken('abc')->get($url);
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toHaveCount(1);
});

it('flags file_get_contents on a user url', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            $url = $request->input('url');
            return file_get_contents($url);
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toHaveCount(1);
});

it('flags curl_setopt CURLOPT_URL on a user url', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            $ch = curl_init();
            $target = $request->input('url');
            curl_setopt($ch, CURLOPT_URL, $target);
            return curl_exec($ch);
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toHaveCount(1);
});

it('flags a Guzzle $client->request() to a user url', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            $url = $request->input('url');
            return $client->request('GET', $url);
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toHaveCount(1);
});

it('does NOT flag a constant string url', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            return Http::get('https://api.example.com/status');
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toBeEmpty();
});

it('does NOT flag a config-derived url', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            return Http::get(config('services.api.url'));
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toBeEmpty();
});

it('does NOT flag a route() / url() derived url', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            return Http::get(route('webhook'));
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toBeEmpty();
});

it('does NOT flag when the url is validated against an allow-list', function (): void {
    $method = <<<'PHP'
        public function fetch(Request $request)
        {
            $url = $request->input('url');
            if (! in_array($url, ['https://a.test', 'https://b.test'])) {
                abort(403);
            }
            return Http::get($url);
        }
    PHP;

    expect(runSsrfDetector(ssrfController($method)))->toBeEmpty();
});

it('does NOT flag non-controller files', function (): void {
    $files = [[
        'path' => 'app/Services/Fetcher.php',
        'type' => 'other',
        'content' => "<?php\nclass Fetcher { public function go(\$request){ \$u = \$request->input('url'); return Http::get(\$u); } }",
    ]];

    expect(runSsrfDetector($files))->toBeEmpty();
});

it('does NOT flag the clean controller fixture', function (): void {
    $files = [[
        'path' => 'CleanController.php',
        'type' => 'controller',
        'content' => file_get_contents(__DIR__.'/../Fixtures/benchmark/samples/CleanController.php'),
    ]];

    expect(runSsrfDetector($files))->toBeEmpty();
});

it('flags the benchmark SsrfController fixture once at the sink line', function (): void {
    $files = [[
        'path' => 'SsrfController.php',
        'type' => 'controller',
        'content' => file_get_contents(__DIR__.'/../Fixtures/benchmark/samples/SsrfController.php'),
    ]];

    $findings = runSsrfDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Ssrf)
        ->and($findings[0]->line)->toBe(16);
});

it('produces exactly one SSRF finding when the full analyzer runs over the benchmark fixture', function (): void {
    $files = [[
        'path' => 'SsrfController.php',
        'type' => 'controller',
        'content' => file_get_contents(__DIR__.'/../Fixtures/benchmark/samples/SsrfController.php'),
    ]];

    $findings = (new AccessControlAnalyzer)->analyze(
        $files,
        new AccessControlContext,
    );

    $ssrf = array_values(array_filter(
        $findings,
        fn ($f): bool => $f->type === VulnerabilityType::Ssrf,
    ));

    expect($ssrf)->toHaveCount(1)
        ->and($ssrf[0]->line)->toBe(16);
});

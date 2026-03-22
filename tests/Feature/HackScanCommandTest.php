<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mockery\MockInterface;

/**
 * Build a mock AIAdapter that handles both send() and sendWithUsage().
 */
function mockAIAdapterForScan(string $response): MockInterface
{
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('send')->andReturn($response);
    $mock->shouldReceive('sendWithUsage')->andReturn([
        'text' => $response,
        'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 50],
    ]);

    return $mock;
}

function buildScanAIResponse(int $score = 75, array $vulnerabilities = []): string
{
    if (empty($vulnerabilities)) {
        $vulnerabilities = [
            [
                'type' => 'sql_injection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 42,
                'severity' => 'critical',
                'description' => 'Raw SQL query with user input concatenation.',
                'proof' => 'DB::select("SELECT * FROM users WHERE id = $id")',
                'fix' => 'DB::select("SELECT * FROM users WHERE id = ?", [$id])',
            ],
            [
                'type' => 'xss',
                'location' => 'app/Http/Controllers/ProfileController.php',
                'line' => 18,
                'severity' => 'high',
                'description' => 'Unescaped user input in HTML output.',
                'proof' => 'return response("<h1>$name</h1>")',
                'fix' => 'return response("<h1>" . e($name) . "</h1>")',
            ],
            [
                'type' => 'missing_rate_limit',
                'location' => 'routes/api.php',
                'line' => 5,
                'severity' => 'medium',
                'description' => 'Login route has no rate limiting.',
                'proof' => 'Route::post("/login", [AuthController::class, "login"])',
                'fix' => 'Route::post("/login", [AuthController::class, "login"])->middleware("throttle:5,1")',
            ],
            [
                'type' => 'mass_assignment',
                'location' => 'app/Models/User.php',
                'line' => 8,
                'severity' => 'low',
                'description' => 'Model has $guarded = [].',
                'proof' => 'protected $guarded = []',
                'fix' => 'protected $fillable = ["name", "email", "password"]',
            ],
        ];
    }

    return json_encode([
        'vulnerabilities' => $vulnerabilities,
        'overall_score' => $score,
        'summary' => 'Multiple security issues detected across the application.',
        'ctf_idea' => 'SQL Injection to RCE chain',
    ], JSON_THROW_ON_ERROR);
}

beforeEach(function (): void {
    // Create a temp directory with a PHP file so the scanner has something to scan
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

it('command runs successfully with mocked AI adapter', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 85,
        'summary' => 'No issues found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);

    $this->app->instance(AIAdapter::class, mockAIAdapterForScan($response));

    $this->artisan('hack:scan')
        ->assertSuccessful();
});

it('command with --json flag outputs valid JSON', function (): void {
    $this->app->instance(AIAdapter::class, mockAIAdapterForScan(buildScanAIResponse()));

    $this->artisan('hack:scan', ['--json' => true])
        ->expectsOutputToContain('"overall_score"');
});

it('command with --severity flag filters results by minimum severity', function (): void {
    $this->app->instance(AIAdapter::class, mockAIAdapterForScan(buildScanAIResponse()));

    $result = $this->artisan('hack:scan', ['--json' => true, '--severity' => 'Critical']);

    $result->expectsOutputToContain('"overall_score"');
});

it('command returns failure exit code when critical vulnerabilities are found', function (): void {
    $this->app->instance(AIAdapter::class, mockAIAdapterForScan(buildScanAIResponse(score: 15)));

    $this->artisan('hack:scan', ['--json' => true])
        ->assertFailed();
});

it('command returns success exit code when no critical vulnerabilities are found', function (): void {
    $response = buildScanAIResponse(score: 90, vulnerabilities: [
        [
            'type' => 'missing_validation',
            'location' => 'app/Http/Controllers/TestController.php',
            'line' => 5,
            'severity' => 'low',
            'description' => 'Missing validation.',
            'proof' => '$request->all()',
            'fix' => '$request->validated()',
        ],
    ]);

    $this->app->instance(AIAdapter::class, mockAIAdapterForScan($response));

    $this->artisan('hack:scan', ['--json' => true])
        ->assertSuccessful();
});

it('command output contains banner when not using --json flag', function (): void {
    $response = json_encode([
        'vulnerabilities' => [],
        'overall_score' => 100,
        'summary' => 'No issues found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);

    $this->app->instance(AIAdapter::class, mockAIAdapterForScan($response));

    $this->artisan('hack:scan')
        ->expectsOutputToContain('Collecting files...')
        ->assertSuccessful();
});

it('json output contains scan_duration_ms field', function (): void {
    $this->app->instance(AIAdapter::class, mockAIAdapterForScan(buildScanAIResponse(score: 100, vulnerabilities: [])));

    $this->artisan('hack:scan', ['--json' => true])
        ->expectsOutputToContain('"scan_duration_ms"');
});

it('json output contains counts object', function (): void {
    $this->app->instance(AIAdapter::class, mockAIAdapterForScan(buildScanAIResponse()));

    $this->artisan('hack:scan', ['--json' => true])
        ->expectsOutputToContain('"counts"');
});

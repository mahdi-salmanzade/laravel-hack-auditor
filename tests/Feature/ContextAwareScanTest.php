<?php

declare(strict_types=1);

use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\AI\ResponseParser;
use Mahdi\HackAuditor\Scanner\AppContext;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\ContextCollector;
use Mahdi\HackAuditor\Scanner\FileCollector;
use Mahdi\HackAuditor\Scanner\HackScanner;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

beforeEach(function (): void {
    $this->tempDir = sys_get_temp_dir().'/hack-auditor-test-'.uniqid();
    mkdir($this->tempDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);
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

it('context collector provides app context to prompt builder', function (): void {
    $appContext = new AppContext(
        routes: ['UserController@index' => ['method' => 'GET', 'uri' => '/users', 'middleware' => ['auth:sanctum']]],
        middlewareDefinitions: ['auth:sanctum' => 'Sanctum token authentication'],
        globalMiddleware: ['HandleCors'],
        rateLimiters: [],
        policies: [],
        formRequests: [],
        models: [],
        configContext: [],
        baseControllerMiddleware: [],
        environment: ['app_env' => 'production'],
    );

    $promptBuilder = new PromptBuilder;
    $promptBuilder->withAppContext($appContext);

    $prompt = $promptBuilder->userPrompt([
        ['path' => 'app/Http/Controllers/UserController.php', 'content' => '<?php class UserController {}', 'type' => 'controller'],
    ]);

    expect($prompt)->toContain('APPLICATION CONTEXT')
        ->and($prompt)->toContain('auth:sanctum')
        ->and($prompt)->toContain('CODE TO AUDIT');
});

it('prompt builder includes app context in user prompt', function (): void {
    $context = new AppContext(
        routes: ['UserController@index' => ['method' => 'GET', 'uri' => '/users', 'middleware' => ['auth:sanctum', 'throttle:60,1']]],
        middlewareDefinitions: ['auth:sanctum' => 'Sanctum token authentication'],
        globalMiddleware: ['HandleCors', 'TrustProxies'],
        rateLimiters: ['api' => '60 per minute'],
        policies: [],
        formRequests: [],
        models: [],
        configContext: [],
        baseControllerMiddleware: [],
        environment: ['app_env' => 'production'],
    );

    $promptBuilder = new PromptBuilder;
    $promptBuilder->withAppContext($context);

    $prompt = $promptBuilder->userPrompt([
        ['path' => 'app/Http/Controllers/UserController.php', 'content' => '<?php class UserController {}', 'type' => 'controller'],
    ]);

    expect($prompt)->toContain('APPLICATION CONTEXT')
        ->and($prompt)->toContain('auth:sanctum')
        ->and($prompt)->toContain('throttle:60,1')
        ->and($prompt)->toContain('CODE TO AUDIT');
});

it('system prompt includes context-aware rules', function (): void {
    $promptBuilder = new PromptBuilder;
    $systemPrompt = $promptBuilder->systemPrompt();

    expect($systemPrompt)->toContain('CONTEXT-FIRST ANALYSIS')
        ->and($systemPrompt)->toContain('NEVER FLAG THESE')
        ->and($systemPrompt)->toContain('FALSE POSITIVE PREVENTION');
});

it('context collector returns empty when disabled', function (): void {
    $this->app['config']->set('hack-auditor.context.enabled', false);

    // Re-create the singleton so it reads the updated config
    $this->app->forgetInstance(ContextCollector::class);
    $collector = app(ContextCollector::class);
    $result = $collector->collect([]);

    $empty = AppContext::empty();

    expect($result->routes)->toBe($empty->routes)
        ->and($result->middlewareDefinitions)->toBe($empty->middlewareDefinitions)
        ->and($result->globalMiddleware)->toBe($empty->globalMiddleware)
        ->and($result->rateLimiters)->toBe($empty->rateLimiters)
        ->and($result->policies)->toBe($empty->policies)
        ->and($result->formRequests)->toBe($empty->formRequests)
        ->and($result->models)->toBe($empty->models)
        ->and($result->configContext)->toBe($empty->configContext)
        ->and($result->baseControllerMiddleware)->toBe($empty->baseControllerMiddleware)
        ->and($result->environment)->toBe($empty->environment);
});

it('hack scanner injects context collector into prompt', function (): void {
    $capturedUserPrompt = null;

    $mockAdapter = Mockery::mock(AIAdapter::class);
    $mockAdapter->shouldReceive('send')
        ->once()
        ->withArgs(function (string $systemPrompt, string $userPrompt) use (&$capturedUserPrompt): bool {
            $capturedUserPrompt = $userPrompt;

            return true;
        })
        ->andReturn(json_encode([
            'vulnerabilities' => [],
            'overall_score' => 100,
            'summary' => 'No issues found.',
            'ctf_idea' => '',
        ], JSON_THROW_ON_ERROR));

    $appContext = new AppContext(
        routes: ['App\Http\Controllers\UserController@index' => ['method' => 'GET', 'uri' => '/users', 'middleware' => ['auth:sanctum', 'throttle:60,1']]],
        middlewareDefinitions: ['auth:sanctum' => 'Sanctum token authentication'],
        globalMiddleware: ['HandleCors'],
        rateLimiters: ['api' => '60 per minute'],
        policies: [],
        formRequests: [],
        models: [],
        configContext: [],
        baseControllerMiddleware: [],
        environment: ['app_env' => 'production'],
    );

    // Create a controller file in the temp directory
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);

    $controllerCode = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use Illuminate\Routing\Controller;

    class UserController extends Controller
    {
        public function index()
        {
            return \App\Models\User::all();
        }
    }
    PHP;

    $controllerPath = $controllerDir.'/UserController.php';
    file_put_contents($controllerPath, $controllerCode);

    // Point base path to the temp directory
    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);

    $scanner = new HackScanner(
        fileCollector: app(FileCollector::class),
        codeExtractor: app(CodeExtractor::class),
        promptBuilder: app(PromptBuilder::class),
        responseParser: app(ResponseParser::class),
        aiAdapter: $mockAdapter,
    );

    // Inject appContext directly via reflection to bypass final ContextCollector
    $appContextProp = new ReflectionProperty(HackScanner::class, 'appContext');
    $appContextProp->setValue($scanner, $appContext);

    $report = $scanner->scanFile($controllerPath);

    expect($report)->toBeInstanceOf(VulnerabilityReport::class)
        ->and($capturedUserPrompt)->toContain('APPLICATION CONTEXT')
        ->and($capturedUserPrompt)->toContain('auth:sanctum')
        ->and($capturedUserPrompt)->toContain('throttle:60,1');
});

it('app context truncates to token budget', function (): void {
    // Build a large AppContext with many routes
    $routes = [];
    for ($i = 0; $i < 200; $i++) {
        $routes["Controller{$i}@action{$i}"] = [
            'method' => 'GET',
            'uri' => "/resource-{$i}/with-a-long-path-segment/and-more",
            'middleware' => ['auth:sanctum', 'throttle:60,1', 'verified', 'can:viewAny,resource'],
        ];
    }

    $models = [];
    for ($i = 0; $i < 50; $i++) {
        $models["App\\Models\\Model{$i}"] = [
            'fillable' => ['name', 'email', 'description', 'content', 'status'],
            'hidden' => ['password', 'remember_token'],
            'guarded' => [],
            'casts' => ['email_verified_at' => 'datetime', 'settings' => 'array'],
            'traits' => ['HasFactory', 'SoftDeletes', 'HasApiTokens'],
        ];
    }

    $largeContext = new AppContext(
        routes: $routes,
        middlewareDefinitions: ['auth:sanctum' => 'Sanctum token authentication', 'throttle' => 'Rate limiting', 'verified' => 'Email verified'],
        globalMiddleware: ['HandleCors', 'TrustProxies', 'PreventRequestsDuringMaintenance'],
        rateLimiters: ['api' => '60 per minute', 'uploads' => '10 per minute'],
        policies: [],
        formRequests: [],
        models: $models,
        configContext: ['auth' => ['defaults' => ['guard' => 'web']]],
        baseControllerMiddleware: [],
        environment: ['app_env' => 'production', 'app_debug' => 'false'],
    );

    // The large context should exceed 500 tokens
    expect($largeContext->estimateTokens())->toBeGreaterThan(500);

    $truncated = $largeContext->truncateToTokenBudget(500);
    $promptString = $truncated->toPromptString();

    // 500 tokens * 4 chars per token = 2000 chars max
    expect(strlen($promptString))->toBeLessThanOrEqual(2000);
});

it('backward compatibility: existing route context still works', function (): void {
    $promptBuilder = new PromptBuilder;
    $promptBuilder->withRouteContext(['GET /users' => ['auth']]);

    $prompt = $promptBuilder->userPrompt([
        ['path' => 'app/Http/Controllers/UserController.php', 'content' => '<?php class UserController {}', 'type' => 'controller'],
    ]);

    expect($prompt)->toContain('Route Middleware Context')
        ->and($prompt)->toContain('auth');
});

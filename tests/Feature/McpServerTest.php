<?php

declare(strict_types=1);

use Illuminate\Testing\Fluent\AssertableJson;
use Laravel\Mcp\Server\McpServiceProvider;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\Mcp\HackAuditorMcpServer;
use Mahdi\HackAuditor\Mcp\Tools\ExplainFindingTool;
use Mahdi\HackAuditor\Mcp\Tools\ScanDiffTool;
use Mahdi\HackAuditor\Mcp\Tools\ScanPathTool;
use Mahdi\HackAuditor\Scanner\GitDiffCollector;

/**
 * Canned AI response containing a single, known SQL injection finding.
 */
function fakeScanResponse(): string
{
    return json_encode([
        'vulnerabilities' => [
            [
                'type' => 'sql_injection',
                'location' => 'app/Http/Controllers/UserController.php',
                'line' => 42,
                'severity' => 'critical',
                'description' => 'Raw SQL query with user input concatenation.',
                'proof' => 'DB::select("SELECT * FROM users WHERE id = $id")',
                'fix' => 'Use parameter binding: DB::select("... id = ?", [$id])',
            ],
        ],
        'overall_score' => 40,
        'summary' => 'One critical SQL injection found.',
        'ctf_idea' => '',
    ], JSON_THROW_ON_ERROR);
}

/**
 * Bind a fake AIAdapter so the real HackScanner never hits the network.
 */
function fakeAi(string $response): void
{
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldReceive('send')->andReturn($response);
    $mock->shouldReceive('sendWithUsage')->andReturn([
        'text' => $response,
        'usage' => ['prompt_tokens' => 100, 'completion_tokens' => 50],
    ]);

    app()->instance(AIAdapter::class, $mock);
}

beforeEach(function (): void {
    // Laravel MCP's service provider installs the resolving callback that
    // copies tool-call arguments into the injected Request. Testbench does
    // not auto-register it, so register it explicitly for these tests.
    $this->app->register(McpServiceProvider::class);

    $this->tempDir = sys_get_temp_dir().'/hack-auditor-mcp-test-'.uniqid();
    $controllerDir = $this->tempDir.'/app/Http/Controllers';
    mkdir($controllerDir, 0755, true);
    $this->tempDir = realpath($this->tempDir);

    file_put_contents(
        $this->tempDir.'/app/Http/Controllers/UserController.php',
        '<?php class UserController { public function show($id) { return DB::select("SELECT * FROM users WHERE id = $id"); } }',
    );

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $this->tempDir);
    $this->app['config']->set('hack-auditor.scan.paths', ['app/Http/Controllers']);
});

afterEach(function (): void {
    if (isset($this->tempDir) && is_dir($this->tempDir)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($iterator as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }

        rmdir($this->tempDir);
    }
});

it('scan_path returns structured findings from the scanner', function (): void {
    fakeAi(fakeScanResponse());

    $response = HackAuditorMcpServer::tool(ScanPathTool::class, [
        'path' => 'app/Http/Controllers/UserController.php',
    ]);

    $response
        ->assertOk()
        ->assertSee('SQL Injection')
        ->assertSee('app/Http/Controllers/UserController.php')
        ->assertStructuredContent(function (AssertableJson $json): void {
            $json->where('overall_score', 40)
                ->where('counts.critical', 1)
                ->where('counts.total', 1)
                ->has('findings', 1)
                ->where('findings.0.type', 'sql_injection')
                ->where('findings.0.severity', 'critical')
                ->where('findings.0.file', 'app/Http/Controllers/UserController.php')
                ->where('findings.0.line', 42)
                ->where('findings.0.cwe', 'CWE-89')
                ->has('findings.0.owasp')
                ->has('findings.0.description')
                ->has('findings.0.proof')
                ->has('findings.0.fix')
                ->etc();
        });
});

it('scan_path with no path triggers a full application scan', function (): void {
    fakeAi(fakeScanResponse());

    HackAuditorMcpServer::tool(ScanPathTool::class, [])
        ->assertOk()
        ->assertSee('SQL Injection');
});

it('scan_path refuses a traversal path and never reads the file', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldNotReceive('send');
    $mock->shouldNotReceive('sendWithUsage');
    app()->instance(AIAdapter::class, $mock);

    HackAuditorMcpServer::tool(ScanPathTool::class, ['path' => '../../.env'])
        ->assertHasErrors();
});

it('scan_path refuses an absolute path and never reads the file', function (): void {
    $mock = Mockery::mock(AIAdapter::class);
    $mock->shouldNotReceive('send');
    $mock->shouldNotReceive('sendWithUsage');
    app()->instance(AIAdapter::class, $mock);

    $response = HackAuditorMcpServer::tool(ScanPathTool::class, ['path' => '/etc/passwd']);

    $response->assertHasErrors();
    $response->assertDontSee('root:');
});

it('scan_diff scans changed files and returns findings', function (): void {
    fakeAi(fakeScanResponse());

    $changed = base_path('app/Http/Controllers/UserController.php');

    app()->instance(GitDiffCollector::class, new class($changed) extends GitDiffCollector
    {
        public function __construct(private string $file) {}

        public function getChangedFiles(string $baseBranch = 'main'): array
        {
            return [$this->file];
        }
    });

    HackAuditorMcpServer::tool(ScanDiffTool::class, ['base' => 'main'])
        ->assertOk()
        ->assertSee('SQL Injection')
        ->assertStructuredContent(function (AssertableJson $json): void {
            $json->where('counts.total', 1)
                ->where('findings.0.type', 'sql_injection')
                ->etc();
        });
});

it('scan_diff reports cleanly when no files changed', function (): void {
    app()->instance(GitDiffCollector::class, new class extends GitDiffCollector
    {
        public function getChangedFiles(string $baseBranch = 'main'): array
        {
            return [];
        }
    });

    HackAuditorMcpServer::tool(ScanDiffTool::class, ['base' => 'develop'])
        ->assertOk()
        ->assertStructuredContent(function (AssertableJson $json): void {
            $json->where('counts.total', 0)
                ->where('summary', fn (string $summary): bool => str_contains($summary, 'develop'))
                ->etc();
        });
});

it('explain_finding returns description, OWASP and CWE for a known type', function (): void {
    HackAuditorMcpServer::tool(ExplainFindingTool::class, ['type' => 'idor'])
        ->assertOk()
        ->assertSee('Insecure Direct Object Reference')
        ->assertSee('A01:2021')
        ->assertSee('CWE-639')
        ->assertStructuredContent(function (AssertableJson $json): void {
            $json->where('type', 'idor')
                ->where('cwe', 'CWE-639')
                ->where('owasp', fn (string $owasp): bool => str_contains($owasp, 'A01:2021'))
                ->etc();
        });
});

it('explain_finding accepts common aliases', function (): void {
    HackAuditorMcpServer::tool(ExplainFindingTool::class, ['type' => 'sqli'])
        ->assertOk()
        ->assertSee('SQL Injection')
        ->assertSee('CWE-89');
});

it('explain_finding errors on an unknown type', function (): void {
    HackAuditorMcpServer::tool(ExplainFindingTool::class, ['type' => 'not_a_real_vuln'])
        ->assertHasErrors();
});

it('explain_finding requires a type argument', function (): void {
    HackAuditorMcpServer::tool(ExplainFindingTool::class, [])
        ->assertHasErrors();
});

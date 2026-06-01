<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SensitiveDataExposureDetector;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 */
function runSensitiveDataDetector(array $files): array
{
    $detector = new SensitiveDataExposureDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, new AccessControlContext);
}

function sensitiveController(string $methods): array
{
    return [[
        'path' => 'app/Http/Controllers/UserController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\User;\nclass UserController\n{\n{$methods}\n}\n",
    ]];
}

it('flags a password hash returned inside response()->json', function (): void {
    $method = <<<'PHP'
        public function profile(int $id)
        {
            $user = User::findOrFail($id);
            return response()->json([
                'name' => $user->name,
                'password_hash' => $user->password,
            ]);
        }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::SensitiveDataExposure)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->line)->toBeGreaterThan(1)
        ->and($findings[0]->description)->toContain('profile');
});

it('flags a secret token exposed in a returned array literal', function (): void {
    $method = <<<'PHP'
        public function token(int $id)
        {
            $user = User::findOrFail($id);
            return [
                'api_secret' => $user->api_secret,
            ];
        }
    PHP;

    expect(runSensitiveDataDetector(sensitiveController($method)))->toHaveCount(1);
});

it('flags a sensitive attribute passed through compact()', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $user = User::findOrFail($id);
            $password = $user->password;
            return view('profile', compact('user', 'password'));
        }
    PHP;

    expect(runSensitiveDataDetector(sensitiveController($method)))->toHaveCount(1);
});

it('flags a *_token attribute by suffix in output', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $user = User::findOrFail($id);
            return response()->json(['reset_token' => $user->reset_token]);
        }
    PHP;

    expect(runSensitiveDataDetector(sensitiveController($method)))->toHaveCount(1);
});

it('does NOT flag hashing request input', function (): void {
    $method = <<<'PHP'
        public function store(Request $request)
        {
            $user = new User();
            $user->password = Hash::make($request->password);
            $user->save();
            return response()->json(['id' => $user->id]);
        }
    PHP;

    expect(runSensitiveDataDetector(sensitiveController($method)))->toBeEmpty();
});

it('does NOT flag assignment to a sensitive model field', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, int $id)
        {
            $user = User::findOrFail($id);
            $user->api_secret = $request->input('secret');
            $user->save();
            return response()->json(['updated' => true]);
        }
    PHP;

    expect(runSensitiveDataDetector(sensitiveController($method)))->toBeEmpty();
});

it('does NOT flag Hash::check comparing a stored password', function (): void {
    $method = <<<'PHP'
        public function login(Request $request)
        {
            $user = User::where('email', $request->email)->first();
            if (Hash::check($request->password, $user->password)) {
                return response()->json(['ok' => true]);
            }
            return response()->json(['ok' => false]);
        }
    PHP;

    expect(runSensitiveDataDetector(sensitiveController($method)))->toBeEmpty();
});

it('does NOT flag a sensitive field listed only in $hidden/$fillable config', function (): void {
    $model = [[
        'path' => 'app/Models/User.php',
        'type' => 'model',
        'content' => "<?php\nnamespace App\\Models;\nclass User\n{\n    protected \$fillable = ['name', 'email', 'password'];\n    protected \$hidden = ['password', 'remember_token'];\n}\n",
    ]];

    expect(runSensitiveDataDetector($model))->toBeEmpty();
});

it('does NOT flag a sensitive attribute read outside of output context', function (): void {
    $method = <<<'PHP'
        public function rotate(int $id)
        {
            $user = User::findOrFail($id);
            $current = $user->api_secret;
            Log::channel('audit')->info('rotated');
            return response()->json(['rotated' => true]);
        }
    PHP;

    expect(runSensitiveDataDetector(sensitiveController($method)))->toBeEmpty();
});

it('does NOT flag the clean controller and clean model fixtures', function (): void {
    $files = [
        [
            'path' => 'CleanController.php',
            'type' => 'controller',
            'content' => file_get_contents(__DIR__.'/../Fixtures/benchmark/samples/CleanController.php'),
        ],
        [
            'path' => 'CleanModel.php',
            'type' => 'model',
            'content' => file_get_contents(__DIR__.'/../Fixtures/benchmark/samples/CleanModel.php'),
        ],
    ];

    expect(runSensitiveDataDetector($files))->toBeEmpty();
});

it('flags the benchmark SensitiveDataController fixture once around line 18', function (): void {
    $files = [[
        'path' => 'SensitiveDataController.php',
        'type' => 'controller',
        'content' => file_get_contents(__DIR__.'/../Fixtures/benchmark/samples/SensitiveDataController.php'),
    ]];

    $findings = runSensitiveDataDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::SensitiveDataExposure)
        ->and($findings[0]->line)->toBe(18);
});

it('produces exactly one sensitive-data finding when the full analyzer runs over the benchmark fixture', function (): void {
    $files = [[
        'path' => 'SensitiveDataController.php',
        'type' => 'controller',
        'content' => file_get_contents(__DIR__.'/../Fixtures/benchmark/samples/SensitiveDataController.php'),
    ]];

    $findings = (new AccessControlAnalyzer)->analyze(
        $files,
        new AccessControlContext,
    );

    $sensitive = array_values(array_filter(
        $findings,
        fn ($f): bool => $f->type === VulnerabilityType::SensitiveDataExposure,
    ));

    expect($sensitive)->toHaveCount(1)
        ->and($sensitive[0]->line)->toBe(18);
});

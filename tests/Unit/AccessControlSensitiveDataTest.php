<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SensitiveDataExposureDetector;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Support\Confidence;
use Mahdi\HackAuditor\Support\FindingClass;
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

/*
|--------------------------------------------------------------------------
| Precision regressions
|--------------------------------------------------------------------------
|
| Each test below pins one defect class the previous, regex-over-source
| implementation shipped: a pattern that matched inside comments and string
| literals, an output "region" bounded by counting brackets in raw text, a
| receiver whose type was never established, a line taken from a byte offset,
| and advice that told the reader to apply a control that does not apply.
|
*/

/**
 * Build a single-file controller fixture from complete source.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function sensitiveSource(string $content, string $path = 'app/Http/Controllers/ReportController.php'): array
{
    return [['path' => $path, 'content' => $content, 'type' => 'controller']];
}

/**
 * The 1-based line of the first line containing the needle.
 */
function sensitiveLineContaining(string $content, string $needle): int
{
    foreach (explode("\n", $content) as $index => $line) {
        if (str_contains($line, $needle)) {
            return $index + 1;
        }
    }

    throw new RuntimeException('needle not present in fixture: '.$needle);
}

/**
 * Load the clean precision corpus in the shape the detector consumes.
 *
 * @return array<int, array{path: string, content: string, type: string}>
 */
function sensitiveDataPrecisionFiles(): array
{
    $root = dirname(__DIR__).'/Fixtures/precision';
    $files = [];

    /** @var iterable<SplFileInfo> $iterator */
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace(DIRECTORY_SEPARATOR, '/', str_replace($root.DIRECTORY_SEPARATOR, '', $file->getPathname()));

        $files[] = [
            'path' => $relative,
            'content' => (string) file_get_contents($file->getPathname()),
            'type' => match (true) {
                str_contains($relative, 'Http/Controllers/') => 'controller',
                str_contains($relative, 'Models/') => 'model',
                str_starts_with($relative, 'routes/') => 'route',
                default => 'other',
            },
        ];
    }

    return $files;
}

it('reports nothing for any file in the clean precision corpus', function (): void {
    $claims = array_map(
        fn ($v): string => sprintf('%s:%d %s', $v->location, $v->line, $v->description),
        runSensitiveDataDetector(sensitiveDataPrecisionFiles()),
    );

    expect($claims)->toBe([]);
});

it('does NOT read an attribute name out of a comment or a string literal', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;

    class ReportController
    {
        public function show(int $id)
        {
            $user = User::findOrFail($id);

            // Never return $user->password from this endpoint.
            return response()->json([
                'name' => $user->name,
                'hint' => 'the field $user->api_secret is deliberately omitted',
            ]);
        }
    }
    PHP;

    expect(runSensitiveDataDetector(sensitiveSource($content)))->toBeEmpty();
});

it('does NOT treat a secret-sounding array KEY as a read of that attribute', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;

    class ReportController
    {
        public function show(int $id)
        {
            $user = User::findOrFail($id);

            return response()->json([
                'api_secret' => null,
                'password' => '[redacted]',
                'remember_token' => $user->name,
            ]);
        }
    }
    PHP;

    expect(runSensitiveDataDetector(sensitiveSource($content)))->toBeEmpty();
});

it('does NOT treat Eloquent eager loading as view data (->with is not a sink)', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Post;
    use App\Models\User;

    class ReportController
    {
        public function index(int $id)
        {
            $user = User::findOrFail($id);
            $posts = Post::query()->with(['author', $user->api_secret])->get();

            return response()->json(['total' => count($posts)]);
        }
    }
    PHP;

    expect(runSensitiveDataDetector(sensitiveSource($content)))->toBeEmpty();
});

it('does flag view()->with([...]) view data, which IS a sink', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;

    class ReportController
    {
        public function show(int $id)
        {
            $user = User::findOrFail($id);

            return view('profile')->with(['secret' => $user->api_secret]);
        }
    }
    PHP;

    expect(runSensitiveDataDetector(sensitiveSource($content)))->toHaveCount(1);
});

it('does NOT flag an attribute read from an object whose type is never established', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Services\PaymentGateway;

    class ReportController
    {
        public function __construct(private readonly PaymentGateway $gateway) {}

        public function show(): array
        {
            $settings = $this->loadSettings();

            return [
                'gateway' => $this->gateway->api_key,
                'legacy' => $settings->client_secret,
            ];
        }

        private function loadSettings(): object
        {
            return (object) [];
        }
    }
    PHP;

    expect(runSensitiveDataDetector(sensitiveSource($content)))->toBeEmpty();
});

it('reports the exact line of the attribute node, not a byte offset into the body', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;

    class ReportController
    {
        /**
         * Build the report.
         *
         * @param  string  $window  Display window, e.g. "today (utc)"
         */
        public function build(
            int $id,
            string $window = 'today (utc)',
        ): array {
            $user = User::findOrFail($id);

            return [
                'name' => $user->name,
                'api_secret' => $user->api_secret,
            ];
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content));
    $expected = sensitiveLineContaining($content, "'api_secret' => \$user->api_secret");

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe($expected);
});

it('treats status, type, a bare token and structural *_key names as NOT sensitive', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Job;

    class ReportController
    {
        public function show(int $id)
        {
            $job = Job::findOrFail($id);

            return response()->json([
                'status' => $job->status,
                'type' => $job->type,
                'token' => $job->token,
                'key' => $job->key,
                'cache_key' => $job->cache_key,
                'sort_key' => $job->sort_key,
                'route_key' => $job->route_key,
                'foreign_key' => $job->foreign_key,
                'public_key' => $job->public_key,
                'csrf' => $job->csrf_token,
            ]);
        }
    }
    PHP;

    expect(runSensitiveDataDetector(sensitiveSource($content)))->toBeEmpty();
});

it('does NOT flag returning the model itself, which Eloquent redacts through $hidden', function (): void {
    $files = [
        [
            'path' => 'app/Models/User.php',
            'type' => 'model',
            'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass User extends Model\n{\n    protected \$hidden = ['password', 'remember_token'];\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Models\User;

            class ReportController
            {
                public function show(int $id)
                {
                    $user = User::findOrFail($id);

                    return response()->json($user);
                }

                public function asArray(int $id)
                {
                    return response()->json(User::findOrFail($id)->toArray());
                }
            }
            PHP,
        ],
    ];

    expect(runSensitiveDataDetector($files))->toBeEmpty();
});

it('does NOT flag a payload built by an API Resource, which whitelists its own fields', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Http\Resources\UserResource;
    use App\Models\User;

    class ReportController
    {
        public function show(int $id)
        {
            return new UserResource(User::findOrFail($id));
        }

        public function index()
        {
            return UserResource::collection(User::all());
        }
    }
    PHP;

    expect(runSensitiveDataDetector(sensitiveSource($content)))->toBeEmpty();
});

it('flags getAttributes() in a payload because it bypasses the $hidden the model declares', function (): void {
    $files = [
        [
            'path' => 'app/Models/User.php',
            'type' => 'model',
            'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass User extends Model\n{\n    protected \$hidden = ['password', 'remember_token'];\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Models\User;

            class ReportController
            {
                public function show(int $id)
                {
                    $user = User::findOrFail($id);

                    return response()->json($user->getAttributes());
                }
            }
            PHP,
        ],
    ];

    $findings = runSensitiveDataDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::SensitiveDataExposure)
        ->and($findings[0]->description)->toContain('password')
        ->and($findings[0]->proof)->toContain('$hidden');
});

it('stays silent about getAttributes() when no $hidden proves a secret column exists', function (): void {
    $files = [
        [
            'path' => 'app/Models/Tag.php',
            'type' => 'model',
            'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Tag extends Model\n{\n    protected \$fillable = ['name'];\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Models\Tag;

            class ReportController
            {
                public function show(int $id)
                {
                    return response()->json(Tag::findOrFail($id)->getAttributes());
                }
            }
            PHP,
        ],
    ];

    expect(runSensitiveDataDetector($files))->toBeEmpty();
});

it('never advises $hidden as the remedy for an explicit attribute read', function (): void {
    $method = <<<'PHP'
        public function profile(int $id)
        {
            $user = User::findOrFail($id);

            return response()->json(['password_hash' => $user->password]);
        }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->fix)->toContain('does NOT stop this')
        ->and($findings[0]->fix)->not->toContain('authorize(')
        ->and($findings[0]->fix)->toContain('profile');
});

it('emits nothing for a file that cannot be parsed instead of guessing', function (): void {
    $files = [[
        'path' => 'app/Http/Controllers/Broken.php',
        'type' => 'controller',
        'content' => "<?php\nclass Broken {\n    public function show() { return response()->json(['p' => \$user->password]);\n",
    ]];

    expect(runSensitiveDataDetector($files))->toBeEmpty();
});

it('analyses __invoke, the action of a single-action controller', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;

    class ShowSecretController
    {
        public function __invoke(int $id)
        {
            $user = User::findOrFail($id);

            return response()->json(['secret' => $user->api_secret]);
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content, 'app/Http/Controllers/ShowSecretController.php'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('__invoke');
});

it('flags makeVisible() re-exposing a column the model declares hidden, and advises removing that call', function (): void {
    $files = [
        [
            'path' => 'app/Models/User.php',
            'type' => 'model',
            'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass User extends Model\n{\n    protected \$hidden = ['password', 'remember_token'];\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Models\User;

            class ReportController
            {
                public function show(int $id)
                {
                    $user = User::findOrFail($id);

                    return response()->json($user->makeVisible('password'));
                }
            }
            PHP,
        ],
    ];

    $findings = runSensitiveDataDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('password')
        ->and($findings[0]->fix)->toContain('makeVisible')
        ->and($findings[0]->fix)->toContain('User::$hidden')
        ->and($findings[0]->fix)->not->toContain('authorize(');
});

it('stays silent about makeVisible() for a column the model never hid', function (): void {
    $files = [
        [
            'path' => 'app/Models/User.php',
            'type' => 'model',
            'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass User extends Model\n{\n    protected \$hidden = ['remember_token'];\n}\n",
        ],
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Models\User;

            class ReportController
            {
                public function show(int $id)
                {
                    return response()->json(User::findOrFail($id)->makeVisible('internal_notes'));
                }
            }
            PHP,
        ],
    ];

    expect(runSensitiveDataDetector($files))->toBeEmpty();
});

/*
|--------------------------------------------------------------------------
| The two-class model
|--------------------------------------------------------------------------
|
| This detector used to set no findingClass at all, so every single thing it
| emitted defaulted to FindingClass::Vulnerability — an ASSERTION — and carried
| a "Remove 'x' from the payload" fix. Its one assertion across 6,221 real files
| was wrong, and it produced four further destructive fixes on an adversarial
| corpus. The tests below pin each link of the evidence chain that must hold
| before an assertion is allowed, and pin the fact that everything short of it
| is a QUESTION with no fix attached.
|
*/

/**
 * A model that declares its secrets with PHP attributes rather than properties,
 * which is how Laravel 12 models are written.
 *
 * @return array{path: string, content: string, type: string}
 */
function attributeRedactedUserModel(): array
{
    return [
        'path' => 'app/Models/User.php',
        'type' => 'model',
        'content' => <<<'PHP'
        <?php

        namespace App\Models;

        use Illuminate\Database\Eloquent\Attributes\Guarded;
        use Illuminate\Database\Eloquent\Attributes\Hidden;
        use Illuminate\Database\Eloquent\Model;

        #[Guarded(['id', 'subsonic_api_key'])]
        #[Hidden(['password', 'remember_token', 'subsonic_api_key'])]
        class User extends Model
        {
        }
        PHP,
    ];
}

it('never asserts a value wrapped in $this->when(), which removeMissingValues() strips', function (): void {
    $files = [
        attributeRedactedUserModel(),
        [
            'path' => 'app/Http/Resources/UserResource.php',
            'type' => 'other',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Resources;

            use App\Models\User;
            use Illuminate\Http\Request;
            use Illuminate\Http\Resources\Json\JsonResource;

            class UserResource extends JsonResource
            {
                public function __construct(private readonly User $user)
                {
                    parent::__construct($user);
                }

                public function toArray(Request $request): array
                {
                    return [
                        'name' => $this->user->name,
                        'subsonic_api_key' => $this->when($request->boolean('full'), fn () => $this->user->subsonic_api_key),
                    ];
                }
            }
            PHP,
        ],
    ];

    $findings = runSensitiveDataDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isReviewItem())->toBeTrue()
        ->and($findings[0]->isConfirmedVulnerability())->toBeFalse()
        ->and($findings[0]->confidence)->toBe(Confidence::Possible)
        ->and($findings[0]->fix)->toBe('')
        ->and($findings[0]->description)->toStartWith('Does UserResource::toArray()')
        ->and($findings[0]->proof)->toContain('MissingValue')
        ->and($findings[0]->proof)->not->toContain('directly');
});

it('reports nothing at all when the when() condition resolves to an ownership check', function (): void {
    $files = [
        attributeRedactedUserModel(),
        [
            'path' => 'app/Http/Resources/UserResource.php',
            'type' => 'other',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Resources;

            use App\Models\User;
            use Illuminate\Http\Request;
            use Illuminate\Http\Resources\Json\JsonResource;

            class UserResource extends JsonResource
            {
                public const JSON_STRUCTURE = ['name', 'subsonic_api_key'];

                public function __construct(private readonly User $user)
                {
                    parent::__construct($user);
                }

                public function toArray(Request $request): array
                {
                    $currentUser = $request->user();
                    $isCurrentUser = $this->user->is($currentUser);

                    return [
                        'name' => $this->user->name,
                        'subsonic_api_key' => $this->when($isCurrentUser, fn () => $this->user->subsonic_api_key),
                    ];
                }
            }
            PHP,
        ],
    ];

    expect(runSensitiveDataDetector($files))->toBeEmpty();
});

it('never asserts a secret the caller reads from their own record', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use Illuminate\Http\Request;

    class ApiCredentialController
    {
        public function edit(Request $request)
        {
            $user = $request->user();

            return view('settings.api', [
                'api_key' => $user->api_key,
            ]);
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content, 'app/Http/Controllers/ApiCredentialController.php'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isReviewItem())->toBeTrue()
        ->and($findings[0]->fix)->toBe('')
        ->and($findings[0]->proof)->toContain("authenticated caller's own record")
        ->and($findings[0]->description)->toContain('self-disclosure');
});

it('never asserts a read the same method already gated with authorize()', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Note;
    use Illuminate\Http\Request;

    class NoteShareController
    {
        public function store(Request $request, Note $note)
        {
            $this->authorize('share', $note);

            return response()->json([
                'share_token' => $note->share_token,
            ]);
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content, 'app/Http/Controllers/NoteShareController.php'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isReviewItem())->toBeTrue()
        ->and($findings[0]->fix)->toBe('')
        ->and($findings[0]->description)->toContain('authorize() on line');
});

it('never asserts a value that a helper call derives before the payload sees it', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Note;

    class NoteShareController
    {
        public function show(Note $note)
        {
            return response()->json([
                'share_url' => route('notes.shared', $note->share_token),
                'fingerprint' => substr($note->api_secret, -4),
            ]);
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content, 'app/Http/Controllers/NoteShareController.php'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isReviewItem())->toBeTrue()
        ->and($findings[0]->fix)->toBe('')
        ->and($findings[0]->description)->toContain('route()')
        ->and($findings[0]->proof)->not->toContain('directly');
});

it('does NOT treat a bare array returned by a queued job as a response', function (): void {
    $files = [[
        'path' => 'app/Jobs/SyncIntegrationJob.php',
        'type' => 'other',
        'content' => <<<'PHP'
        <?php

        namespace App\Jobs;

        use App\Models\Integration;

        class SyncIntegrationJob
        {
            public function __construct(private readonly Integration $integration) {}

            public function headers(): array
            {
                return [
                    'Authorization' => 'Bearer '.$this->integration->api_key,
                ];
            }
        }
        PHP,
    ]];

    expect(runSensitiveDataDetector($files))->toBeEmpty();
});

it('DOES flag the same array shape when the class is the thing answering the request', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Integration;

    class IntegrationController
    {
        public function __construct(private readonly Integration $integration) {}

        public function show(): array
        {
            return [
                'authorization' => 'Bearer '.$this->integration->api_key,
            ];
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content, 'app/Http/Controllers/IntegrationController.php'));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isConfirmedVulnerability())->toBeTrue()
        ->and($findings[0]->confidence)->toBe(Confidence::Proven)
        ->and($findings[0]->mayCarryFix())->toBeTrue()
        ->and($findings[0]->hasFix())->toBeTrue();
});

it('asserts a proven leak at Proven confidence and keeps its fix', function (): void {
    $method = <<<'PHP'
        public function profile(int $id)
        {
            $user = User::findOrFail($id);

            return response()->json([
                'password_hash' => $user->password,
            ]);
        }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->findingClass)->toBe(FindingClass::Vulnerability)
        ->and($findings[0]->confidence)->toBe(Confidence::Proven)
        ->and($findings[0]->proof)->toContain('no when()/unless() wrapper')
        ->and($findings[0]->proof)->toContain('$hidden does not redact this read')
        ->and($findings[0]->fix)->toContain("Remove 'password'");
});

it('reads #[Hidden] as well as $hidden when deciding what a model declares secret', function (): void {
    $files = [
        attributeRedactedUserModel(),
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Models\User;

            class ReportController
            {
                public function show(int $id)
                {
                    return response()->json(User::findOrFail($id)->getAttributes());
                }
            }
            PHP,
        ],
    ];

    $findings = runSensitiveDataDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isConfirmedVulnerability())->toBeTrue()
        ->and($findings[0]->description)->toContain('password')
        ->and($findings[0]->proof)->toContain('#[Hidden]');
});

it('names the model redaction declaration in the proof of an explicit read', function (): void {
    $files = [
        attributeRedactedUserModel(),
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'type' => 'controller',
            'content' => <<<'PHP'
            <?php

            namespace App\Http\Controllers;

            use App\Models\User;

            class ReportController
            {
                public function show(int $id)
                {
                    $user = User::findOrFail($id);

                    return response()->json(['p' => $user->password]);
                }
            }
            PHP,
        ],
    ];

    $findings = runSensitiveDataDetector($files);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isConfirmedVulnerability())->toBeTrue()
        ->and($findings[0]->proof)->toContain("User declares 'password' in #[Hidden]")
        ->and($findings[0]->proof)->toContain('the application itself classifies the column as secret');
});

it('never advises deleting a payload key the file declares as its response contract', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;

    class ReportController
    {
        public const JSON_STRUCTURE = ['name', 'api_secret'];

        public function show(int $id)
        {
            $user = User::findOrFail($id);

            return response()->json([
                'name' => $user->name,
                'api_secret' => $user->api_secret,
            ]);
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isConfirmedVulnerability())->toBeTrue()
        ->and($findings[0]->fix)->toContain('Stop emitting the raw')
        ->and($findings[0]->fix)->not->toContain("Remove 'api_secret' from the payload")
        ->and($findings[0]->proof)->toContain('response-contract constant');
});

it('prefers the provable leak over the open question when a method contains both', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;
    use Illuminate\Http\Request;

    class ReportController
    {
        public function show(Request $request, int $id)
        {
            $me = $request->user();
            $other = User::findOrFail($id);

            return response()->json([
                'mine' => $me->api_secret,
                'theirs' => $other->api_secret,
            ]);
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->isConfirmedVulnerability())->toBeTrue()
        ->and($findings[0]->line)->toBe(sensitiveLineContaining($content, "'theirs'"));
});

it('never attaches a fix to any review-class finding it emits', function (): void {
    $corpus = [
        sensitiveSource(<<<'PHP'
        <?php

        namespace App\Http\Controllers;

        use Illuminate\Http\Request;

        class ReportController
        {
            public function show(Request $request)
            {
                return response()->json(['k' => $request->user()->api_key]);
            }
        }
        PHP),
        sensitiveSource(<<<'PHP'
        <?php

        namespace App\Http\Controllers;

        use App\Models\Note;

        class ReportController
        {
            public function show(Note $note)
            {
                $this->authorize('view', $note);

                return response()->json(['t' => $note->share_token]);
            }
        }
        PHP),
        sensitiveSource(<<<'PHP'
        <?php

        namespace App\Http\Controllers;

        use App\Models\Note;

        class ReportController
        {
            public function show(Note $note)
            {
                return response()->json(['t' => encrypt($note->share_token)]);
            }
        }
        PHP),
    ];

    foreach ($corpus as $files) {
        foreach (runSensitiveDataDetector($files) as $finding) {
            expect($finding->isReviewItem())->toBeTrue()
                ->and($finding->fix)->toBe('')
                ->and($finding->hasFix())->toBeFalse()
                ->and($finding->confidence)->toBe(Confidence::Possible);
        }
    }
});

it('resolves every identifier it names from the analysed file', function (): void {
    $content = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;

    class AuditController
    {
        public function export(int $id)
        {
            $account = User::findOrFail($id);

            return response()->json([
                'secret' => $account->api_secret,
            ]);
        }
    }
    PHP;

    $findings = runSensitiveDataDetector(sensitiveSource($content, 'app/Http/Controllers/AuditController.php'));
    $text = $findings[0]->description.' '.$findings[0]->proof.' '.$findings[0]->fix;

    expect($findings)->toHaveCount(1)
        ->and($text)->toContain('AuditController')
        ->and($text)->toContain('export')
        ->and($text)->toContain('$account')
        ->and($text)->toContain('api_secret')
        ->and($text)->not->toContain('$user')
        ->and($text)->not->toContain('$this->');
});

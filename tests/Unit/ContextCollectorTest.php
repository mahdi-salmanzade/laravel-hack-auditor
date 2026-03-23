<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AppContext;
use Mahdi\HackAuditor\Scanner\ContextCollector;

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

it('returns empty AppContext when context.enabled is false', function (): void {
    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', false);

    $collector = new ContextCollector;
    $result = $collector->collect([]);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->routes)->toBeEmpty()
        ->and($result->middlewareDefinitions)->toBeEmpty()
        ->and($result->globalMiddleware)->toBeEmpty()
        ->and($result->rateLimiters)->toBeEmpty()
        ->and($result->policies)->toBeEmpty()
        ->and($result->formRequests)->toBeEmpty()
        ->and($result->models)->toBeEmpty()
        ->and($result->configContext)->toBeEmpty()
        ->and($result->baseControllerMiddleware)->toBeEmpty()
        ->and($result->environment)->toBeEmpty();
});

it('collects route middleware for controller files', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/api.php', <<<'PHP'
<?php

use App\Http\Controllers\UserController;

Route::middleware(['auth:sanctum'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
    Route::post('/users', [UserController::class, 'store'])->middleware('throttle:60,1');
});
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_routes', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController extends Controller
{
    public function index()
    {
        return response()->json(['users' => []]);
    }

    public function store(Request $request)
    {
        return response()->json(['created' => true]);
    }
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/UserController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->routes)->not->toBeEmpty();

    // Find routes that have auth:sanctum middleware
    $hasAuthSanctum = false;
    $storeHasThrottle = false;

    foreach ($result->routes as $key => $info) {
        $middleware = $info['middleware'] ?? [];

        if (in_array('auth:sanctum', $middleware, true)) {
            $hasAuthSanctum = true;
        }

        if (str_contains($key, 'store') || (isset($info['uri']) && $info['uri'] === '/users' && ($info['method'] ?? '') === 'POST')) {
            if (in_array('throttle:60,1', $middleware, true)) {
                $storeHasThrottle = true;
            }
        }
    }

    expect($hasAuthSanctum)->toBeTrue('Expected routes to contain auth:sanctum middleware')
        ->and($storeHasThrottle)->toBeTrue('Expected store route to have throttle middleware');
});

it('collects middleware definitions from Kernel.php', function (): void {
    $kernelDir = $this->tempDir.'/app/Http';
    mkdir($kernelDir, 0755, true);

    file_put_contents($kernelDir.'/Kernel.php', <<<'PHP'
<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [
            \App\Http\Middleware\EncryptCookies::class,
            \Illuminate\Session\Middleware\StartSession::class,
            \Illuminate\View\Middleware\ShareErrorsFromSession::class,
            \App\Http\Middleware\VerifyCsrfToken::class,
        ],
        'api' => [
            \Illuminate\Routing\Middleware\ThrottleRequests::class.':api',
            \Illuminate\Routing\Middleware\SubstituteBindings::class,
        ],
    ];

    protected $middlewareAliases = [
        'auth' => \App\Http\Middleware\Authenticate::class,
        'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
        'verified' => \App\Http\Middleware\EnsureEmailIsVerified::class,
    ];
}
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_middleware', true);

    $collector = new ContextCollector;
    $result = $collector->collect([]);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->middlewareDefinitions)->not->toBeEmpty();
});

it('collects middleware definitions from bootstrap/app.php', function (): void {
    $bootstrapDir = $this->tempDir.'/bootstrap';
    mkdir($bootstrapDir, 0755, true);

    file_put_contents($bootstrapDir.'/app.php', <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->web(append: [
            \App\Http\Middleware\HandleInertiaRequests::class,
        ]);

        $middleware->api(prepend: [
            \Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful::class,
        ]);

        $middleware->alias([
            'role' => \App\Http\Middleware\CheckRole::class,
        ]);
    })
    ->create();
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_middleware', true);

    $collector = new ContextCollector;
    $result = $collector->collect([]);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and(array_merge($result->middlewareDefinitions, $result->globalMiddleware))->not->toBeEmpty();
});

it('collects policies for models', function (): void {
    $policiesDir = $this->tempDir.'/app/Policies';
    mkdir($policiesDir, 0755, true);

    file_put_contents($policiesDir.'/PostPolicy.php', <<<'PHP'
<?php

namespace App\Policies;

use App\Models\Post;
use App\Models\User;

class PostPolicy
{
    public function view(User $user, Post $post): bool
    {
        return true;
    }

    public function update(User $user, Post $post): bool
    {
        return $user->id === $post->user_id;
    }

    public function delete(User $user, Post $post): bool
    {
        return $user->id === $post->user_id;
    }
}
PHP);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\Post;

class PostController extends Controller
{
    public function show(Post $post)
    {
        return $post;
    }
}
PHP;

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_policies', true);

    $files = [
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->policies)->not->toBeEmpty();

    // Find PostPolicy entry
    $policyFound = false;
    $hasOwnershipCheck = false;

    foreach ($result->policies as $model => $info) {
        if (str_contains($model, 'Post') || str_contains($info['policy'] ?? '', 'PostPolicy')) {
            $policyFound = true;
            $methods = $info['methods'] ?? [];

            expect($methods)->toContain('view')
                ->toContain('update')
                ->toContain('delete');

            if (isset($info['ownership_check'])) {
                $hasOwnershipCheck = $info['ownership_check'];
            }
        }
    }

    expect($policyFound)->toBeTrue('Expected policies to contain PostPolicy')
        ->and($hasOwnershipCheck)->toBeTrue('Expected ownership_check to be true');
});

it('collects form request info', function (): void {
    $requestsDir = $this->tempDir.'/app/Http/Requests';
    mkdir($requestsDir, 0755, true);

    file_put_contents($requestsDir.'/StorePostRequest.php', <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StorePostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->id === $this->route('post')->user_id;
    }

    public function rules(): array
    {
        return [
            'title' => 'required|string',
        ];
    }
}
PHP);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\StorePostRequest;
use App\Models\Post;

class PostController extends Controller
{
    public function store(StorePostRequest $request)
    {
        return Post::create($request->validated());
    }
}
PHP;

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_form_requests', true);

    $files = [
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->formRequests)->not->toBeEmpty();

    // Find StorePostRequest entry
    $requestFound = false;

    foreach ($result->formRequests as $fqcn => $info) {
        if (str_contains($fqcn, 'StorePostRequest')) {
            $requestFound = true;

            expect($info)->toHaveKey('authorize')
                ->toHaveKey('rules')
                ->and($info['authorize'])->toContain('user_id')
                ->and($info['rules'])->toHaveKey('title');
        }
    }

    expect($requestFound)->toBeTrue('Expected formRequests to contain StorePostRequest');
});

it('collects model metadata', function (): void {
    $modelsDir = $this->tempDir.'/app/Models';
    mkdir($modelsDir, 0755, true);

    file_put_contents($modelsDir.'/User.php', <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use SoftDeletes;

    protected $fillable = ['name', 'email'];

    protected $hidden = ['password'];
}
PHP);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function index()
    {
        return User::all();
    }
}
PHP;

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_models', true);

    $files = [
        [
            'path' => 'app/Http/Controllers/UserController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->models)->not->toBeEmpty();

    // Find User model entry
    $modelFound = false;

    foreach ($result->models as $fqcn => $info) {
        if (str_contains($fqcn, 'User')) {
            $modelFound = true;

            expect($info['fillable'])->toContain('name')
                ->toContain('email')
                ->and($info['hidden'])->toContain('password')
                ->and($info['traits'])->toContain('SoftDeletes');
        }
    }

    expect($modelFound)->toBeTrue('Expected models to contain User');
});

it('respects individual context toggles', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\UserController;

Route::get('/users', [UserController::class, 'index'])->middleware('auth');
PHP);

    $policiesDir = $this->tempDir.'/app/Policies';
    mkdir($policiesDir, 0755, true);

    file_put_contents($policiesDir.'/UserPolicy.php', <<<'PHP'
<?php

namespace App\Policies;

use App\Models\User;

class UserPolicy
{
    public function view(User $authUser, User $user): bool
    {
        return true;
    }
}
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_routes', false);
    config()->set('hack-auditor.context.include_policies', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function index()
    {
        return User::all();
    }
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/UserController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->routes)->toBeEmpty();
});

it('handles missing directories gracefully', function (): void {
    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Models\User;

class UserController extends Controller
{
    public function index()
    {
        return User::all();
    }
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/UserController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->routes)->toBeArray()
        ->and($result->middlewareDefinitions)->toBeArray()
        ->and($result->policies)->toBeArray()
        ->and($result->formRequests)->toBeArray()
        ->and($result->models)->toBeArray();
});

it('truncates context to token budget', function (): void {
    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.max_context_tokens', 100);

    // Create lots of context data to exceed the budget
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    $routeLines = "<?php\n\nuse App\\Http\\Controllers\\BigController;\n\n";
    for ($i = 0; $i < 50; $i++) {
        $routeLines .= "Route::get('/endpoint-{$i}', [BigController::class, 'action{$i}'])->middleware('auth', 'verified', 'throttle:60,1');\n";
    }
    file_put_contents($routesDir.'/web.php', $routeLines);

    $policiesDir = $this->tempDir.'/app/Policies';
    mkdir($policiesDir, 0755, true);

    for ($i = 0; $i < 10; $i++) {
        file_put_contents($policiesDir."/Model{$i}Policy.php", <<<PHP
<?php

namespace App\Policies;

class Model{$i}Policy
{
    public function view(\$user, \$model): bool { return true; }
    public function update(\$user, \$model): bool { return \$user->id === \$model->user_id; }
    public function delete(\$user, \$model): bool { return \$user->id === \$model->user_id; }
}
PHP);
    }

    $methods = '';
    for ($i = 0; $i < 50; $i++) {
        $methods .= "    public function action{$i}() { return response()->json([]); }\n";
    }

    $controllerContent = <<<PHP
<?php

namespace App\Http\Controllers;

class BigController extends Controller
{
{$methods}
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/BigController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->estimateTokens())->toBeLessThanOrEqual(100);
});

it('collects config context from auth.php', function (): void {
    $configDir = $this->tempDir.'/config';
    mkdir($configDir, 0755, true);

    file_put_contents($configDir.'/auth.php', <<<'PHP'
<?php

return [
    'defaults' => [
        'guard' => 'web',
        'passwords' => 'users',
    ],

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'sanctum',
            'provider' => 'users',
        ],
    ],

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => \App\Models\User::class,
        ],
    ],
];
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);

    $collector = new ContextCollector;
    $result = $collector->collect([]);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->configContext)->not->toBeEmpty();
});

it('collects rate limiters from service providers', function (): void {
    $providersDir = $this->tempDir.'/app/Providers';
    mkdir($providersDir, 0755, true);

    file_put_contents($providersDir.'/AppServiceProvider.php', <<<'PHP'
<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
        });

        RateLimiter::for('uploads', function (Request $request) {
            return Limit::perMinute(10)->by($request->user()?->id);
        });
    }
}
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);

    $collector = new ContextCollector;
    $result = $collector->collect([]);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->rateLimiters)->not->toBeEmpty()
        ->and($result->rateLimiters)->toHaveKey('api');
});

it('detects invokable controller routes', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\HomeController;

Route::get('/', HomeController::class)->middleware('auth');
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_routes', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

class HomeController extends Controller
{
    public function __invoke()
    {
        return view('home');
    }
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/HomeController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result)->toBeInstanceOf(AppContext::class)
        ->and($result->routes)->toHaveKey('App\Http\Controllers\HomeController@__invoke');

    $route = $result->routes['App\Http\Controllers\HomeController@__invoke'];

    expect($route['method'])->toBe('GET')
        ->and($route['uri'])->toBe('/')
        ->and($route['middleware'])->toContain('auth');
});

it('extracts middleware from Route::prefix()->middleware()->group() chains', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/api.php', <<<'PHP'
<?php

use App\Http\Controllers\AdminController;

Route::prefix('admin')->middleware('auth:sanctum')->group(function () {
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
    Route::post('/settings', [AdminController::class, 'updateSettings']);
});
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_routes', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

class AdminController extends Controller
{
    public function dashboard()
    {
        return view('admin.dashboard');
    }

    public function updateSettings()
    {
        return response()->json(['ok' => true]);
    }
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/AdminController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result->routes)->not->toBeEmpty();

    $dashboardRoute = $result->routes['App\Http\Controllers\AdminController@dashboard'] ?? null;

    expect($dashboardRoute)->not->toBeNull()
        ->and($dashboardRoute['middleware'])->toContain('auth:sanctum')
        ->and($dashboardRoute['uri'])->toBe('/admin/dashboard');

    $settingsRoute = $result->routes['App\Http\Controllers\AdminController@updateSettings'] ?? null;

    expect($settingsRoute)->not->toBeNull()
        ->and($settingsRoute['method'])->toBe('POST')
        ->and($settingsRoute['uri'])->toBe('/admin/settings');
});

it('applies prefix to resource route URIs', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/api.php', <<<'PHP'
<?php

use App\Http\Controllers\PostController;

Route::prefix('api/v1')->middleware('auth')->group(function () {
    Route::apiResource('posts', PostController::class);
});
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_routes', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function index() {}
    public function store() {}
    public function show() {}
    public function update() {}
    public function destroy() {}
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/PostController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    $indexRoute = $result->routes['App\Http\Controllers\PostController@index'] ?? null;

    expect($indexRoute)->not->toBeNull()
        ->and($indexRoute['uri'])->toBe('/api/v1/posts')
        ->and($indexRoute['middleware'])->toContain('auth');
});

it('scans route files in subdirectories', function (): void {
    $routesDir = $this->tempDir.'/routes/api';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/v2.php', <<<'PHP'
<?php

use App\Http\Controllers\ItemController;

Route::get('/items', [ItemController::class, 'index']);
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_routes', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ItemController extends Controller
{
    public function index()
    {
        return [];
    }
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/ItemController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    expect($result->routes)->toHaveKey('App\Http\Controllers\ItemController@index');
});

it('handles Route::group with prefix array key', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\ReportController;

Route::group(['prefix' => 'reports', 'middleware' => 'auth'], function () {
    Route::get('/daily', [ReportController::class, 'daily']);
});
PHP);

    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_routes', true);

    $controllerContent = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ReportController extends Controller
{
    public function daily()
    {
        return [];
    }
}
PHP;

    $files = [
        [
            'path' => 'app/Http/Controllers/ReportController.php',
            'content' => $controllerContent,
            'type' => 'controller',
        ],
    ];

    $collector = new ContextCollector;
    $result = $collector->collect($files);

    $route = $result->routes['App\Http\Controllers\ReportController@daily'] ?? null;

    expect($route)->not->toBeNull()
        ->and($route['uri'])->toBe('/reports/daily')
        ->and($route['middleware'])->toContain('auth');
});

it('returns empty middleware when neither Kernel nor bootstrap/app.php exists', function (): void {
    $this->app->setBasePath($this->tempDir);
    config()->set('hack-auditor.context.enabled', true);
    config()->set('hack-auditor.context.include_middleware', true);

    $collector = new ContextCollector;
    $result = $collector->collect([]);

    expect($result->middlewareDefinitions)->toBeEmpty()
        ->and($result->globalMiddleware)->toBeEmpty();
});

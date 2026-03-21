<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\RouteAnalyzer;

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

it('detects explicit route definitions with middleware', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\UserController;

Route::get('/users', [UserController::class, 'index'])->middleware('auth');
Route::post('/users', [UserController::class, 'store'])->middleware(['auth', 'verified']);
PHP);

    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toHaveKey('GET /users')
        ->and($routes['GET /users'])->toContain('auth')
        ->and($routes)->toHaveKey('POST /users')
        ->and($routes['POST /users'])->toContain('auth')
        ->and($routes['POST /users'])->toContain('verified');
});

it('detects group middleware applied to routes', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\UserController;

Route::middleware(['auth'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});
PHP);

    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toHaveKey('GET /users')
        ->and($routes['GET /users'])->toContain('auth');
});

it('detects apiResource routes', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/api.php', <<<'PHP'
<?php

use App\Http\Controllers\UserController;

Route::apiResource('/users', UserController::class);
PHP);

    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toHaveKey('GET /users')
        ->and($routes)->toHaveKey('POST /users')
        ->and($routes)->toHaveKey('GET /users/{user}')
        ->and($routes)->toHaveKey('PUT /users/{user}')
        ->and($routes)->toHaveKey('PATCH /users/{user}')
        ->and($routes)->toHaveKey('DELETE /users/{user}')
        ->and($routes)->not->toHaveKey('GET /users/create')
        ->and($routes)->not->toHaveKey('GET /users/{user}/edit');
});

it('detects resource routes including create and edit', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\UserController;

Route::resource('/users', UserController::class);
PHP);

    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toHaveKey('GET /users')
        ->and($routes)->toHaveKey('POST /users')
        ->and($routes)->toHaveKey('GET /users/create')
        ->and($routes)->toHaveKey('GET /users/{user}/edit');
});

it('returns empty array when routes directory does not exist', function (): void {
    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toBeArray()->toBeEmpty();
});

it('returns empty array when controller is not referenced in route files', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\PostController;

Route::get('/posts', [PostController::class, 'index']);
PHP);

    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toBeArray()->toBeEmpty();
});

it('combines group middleware with route-level middleware', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', <<<'PHP'
<?php

use App\Http\Controllers\UserController;

Route::middleware(['auth'])->group(function () {
    Route::get('/users', [UserController::class, 'index'])->middleware('verified');
});
PHP);

    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toHaveKey('GET /users')
        ->and($routes['GET /users'])->toContain('auth')
        ->and($routes['GET /users'])->toContain('verified');
});

it('handles empty route files gracefully', function (): void {
    $routesDir = $this->tempDir.'/routes';
    mkdir($routesDir, 0755, true);

    file_put_contents($routesDir.'/web.php', '');

    $this->app->setBasePath($this->tempDir);

    $analyzer = new RouteAnalyzer;
    $routes = $analyzer->analyze('App\\Http\\Controllers\\UserController');

    expect($routes)->toBeArray()->toBeEmpty();
});

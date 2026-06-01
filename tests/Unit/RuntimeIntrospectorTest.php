<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Mahdi\HackAuditor\Scanner\RuntimeIntrospector;

it('returns empty array for unregistered controller', function (): void {
    $introspector = new RuntimeIntrospector(app(Router::class));

    $result = $introspector->getRouteMiddleware('App\\Http\\Controllers\\NonExistentController');

    expect($result)->toBeArray()->toBeEmpty();
});

it('returns empty routed methods for unregistered controller', function (): void {
    $introspector = new RuntimeIntrospector(app(Router::class));

    $result = $introspector->getRoutedMethods('App\\Http\\Controllers\\NonExistentController');

    expect($result)->toBeArray()->toBeEmpty();
});

it('returns null for non-existent model class', function (): void {
    $introspector = new RuntimeIntrospector(app(Router::class));

    $result = $introspector->getModelInfo('App\\Models\\CompletelyFakeModel');

    expect($result)->toBeNull();
});

it('returns null for non-model class', function (): void {
    $introspector = new RuntimeIntrospector(app(Router::class));

    $result = $introspector->getModelInfo(stdClass::class);

    expect($result)->toBeNull();
});

it('degrades gracefully when no routes reference the controller', function (): void {
    $introspector = new RuntimeIntrospector(app(Router::class));

    $middleware = $introspector->getRouteMiddleware('App\\Http\\Controllers\\GhostController');
    $methods = $introspector->getRoutedMethods('App\\Http\\Controllers\\GhostController');

    expect($middleware)->toBeArray()->toBeEmpty()
        ->and($methods)->toBeArray()->toBeEmpty();
});

it('resolves middleware for a routed controller without booting a database', function (): void {
    $router = app(Router::class);

    if (! class_exists('RuntimeIntrospectorRoutedController')) {
        eval('
            class RuntimeIntrospectorRoutedController
            {
                public function index() { return "ok"; }
            }
        ');
    }

    $router->middleware('web')->get(
        '/runtime-introspector-test',
        'RuntimeIntrospectorRoutedController@index',
    );

    $introspector = new RuntimeIntrospector($router);

    $middleware = $introspector->getRouteMiddleware('RuntimeIntrospectorRoutedController');
    $methods = $introspector->getRoutedMethods('RuntimeIntrospectorRoutedController');

    expect($middleware)->toBeArray()
        ->toHaveKey('GET /runtime-introspector-test')
        ->and($middleware['GET /runtime-introspector-test'])->toContain('web')
        ->and($methods)->toBe(['index' => 'GET /runtime-introspector-test']);
});

it('returns model info for a valid eloquent model', function (): void {
    // Define a test model class dynamically
    if (! class_exists('RuntimeIntrospectorTestModel')) {
        eval('
            class RuntimeIntrospectorTestModel extends \Illuminate\Database\Eloquent\Model
            {
                protected $fillable = [\'name\', \'email\'];
                protected $hidden = [\'password\'];
                protected $guarded = [\'id\'];
            }
        ');
    }

    $introspector = new RuntimeIntrospector(app(Router::class));

    $result = $introspector->getModelInfo('RuntimeIntrospectorTestModel');

    expect($result)->toBeArray()
        ->toHaveKeys(['fillable', 'hidden', 'guarded', 'casts'])
        ->and($result['fillable'])->toBe(['name', 'email'])
        ->and($result['hidden'])->toBe(['password'])
        ->and($result['guarded'])->toBe(['id'])
        ->and($result['casts'])->toBeArray();
});

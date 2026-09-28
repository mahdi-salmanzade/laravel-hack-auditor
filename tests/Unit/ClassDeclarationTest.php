<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlAnalyzer;
use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\CodeExtractor;
use Mahdi\HackAuditor\Scanner\HackScanner;

/**
 * Class names and file types are read from tokens.
 *
 * `/class\s+(\w+)/` matched "class" in a `// This class exposes…` comment, so
 * the scanner asked the router about `App\Http\Controllers\exposes`, got no
 * routes, and the IDOR in the real class was silently suppressed. And only a
 * direct `extends Controller` made a file a controller, so an
 * `InvoiceController extends ApiController` was never asked about at all.
 */
function classDeclarationSource(string $comment = '// This class exposes invoices to their owners.'): string
{
    return "<?php\nnamespace App\\Http\\Controllers;\n\nuse App\\Models\\Invoice;\nuse Illuminate\\Http\\Request;\n\n{$comment}\nclass InvoiceController extends Controller\n{\n    public function show(Request \$request, int \$id)\n    {\n        return response()->json(Invoice::findOrFail(\$id));\n    }\n}\n";
}

it('ignores the word "class" in comments, strings, ::class and anonymous classes', function (string $prefix): void {
    $source = "<?php\nnamespace App\\Http\\Controllers;\n{$prefix}\nclass RealController extends BaseController {}\n";

    expect(CodeExtractor::classDeclaration($source))->toBe([
        'namespace' => 'App\Http\Controllers',
        'class' => 'RealController',
        'fqcn' => 'App\Http\Controllers\RealController',
        'extends' => 'BaseController',
    ]);
})->with([
    'line comment' => ['// This class exposes invoices.'],
    'block comment' => ["/* the class below\n is routed */"],
    'docblock' => ["/**\n * A class that exposes things.\n */"],
    'string literal' => ["\$x = 'class Fake';"],
    'class constant' => ['$y = Foo::class;'],
    'anonymous class' => ['$z = new class {};'],
]);

it('resolves the routed class name despite a comment mentioning "class"', function (): void {
    $method = new ReflectionMethod(HackScanner::class, 'extractClassName');
    $scanner = (new ReflectionClass(HackScanner::class))->newInstanceWithoutConstructor();

    expect($method->invoke($scanner, classDeclarationSource()))->toBe('App\Http\Controllers\InvoiceController');

    // With the right name the route table applies and the IDOR is reported.
    $file = [['path' => 'app/Http/Controllers/InvoiceController.php', 'content' => classDeclarationSource(), 'type' => 'controller']];
    $context = new AccessControlContext(routedMethods: [
        $method->invoke($scanner, classDeclarationSource()).'@show' => ['route' => 'GET invoices/{id}', 'middleware' => ['web', 'auth']],
    ]);

    expect((new AccessControlAnalyzer)->analyze($file, $context))->toHaveCount(1);
});

it('returns null when a file declares no class', function (): void {
    expect(CodeExtractor::classDeclaration("<?php\n// class Foo\nfunction helper() { return Bar::class; }\n"))->toBeNull();
});

it('classifies controllers by parent suffix, own name, or directory', function (string $path, string $source, string $expected): void {
    $root = sys_get_temp_dir().'/hack-auditor-type-'.uniqid();
    mkdir(dirname($root.'/'.$path), 0755, true);
    $root = (string) realpath($root);
    file_put_contents($root.'/'.$path, $source);

    $reflector = new ReflectionProperty($this->app, 'basePath');
    $reflector->setValue($this->app, $root);

    $type = (new CodeExtractor)->extract(new SplFileInfo($root.'/'.$path))['type'];

    unlink($root.'/'.$path);

    expect($type)->toBe($expected);
})->with([
    'extends ApiController' => ['app/Http/Controllers/Api/InvoiceController.php', "<?php\nnamespace App\\Http\\Controllers\\Api;\nclass InvoiceController extends ApiController {}\n", 'controller'],
    'extends BaseController' => ['src/Billing/Billing.php', "<?php\nclass Billing extends BaseController {}\n", 'controller'],
    'named *Controller, no parent' => ['src/Web/PageController.php', "<?php\nclass PageController {}\n", 'controller'],
    'under app/Http/Controllers' => ['app/Http/Controllers/Invokable.php', "<?php\nclass Invokable { public function __invoke() {} }\n", 'controller'],
    'User extends Authenticatable' => ['app/Models/User.php', "<?php\nuse Illuminate\\Foundation\\Auth\\User as Authenticatable;\nclass User extends Authenticatable {}\n", 'model'],
    'model under app/Models' => ['app/Models/Invoice.php', "<?php\nclass Invoice extends BaseModel {}\n", 'model'],
    'request extends BaseFormRequest' => ['app/Http/Requests/StoreInvoice.php', "<?php\nclass StoreInvoice extends BaseFormRequest {}\n", 'request'],
    'middleware directory' => ['app/Http/Middleware/EnsureTeam.php', "<?php\nclass EnsureTeam { public function handle(\$r, \$n) {} }\n", 'middleware'],
    'plain service' => ['app/Services/Billing.php', "<?php\nclass Billing {}\n", 'other'],
    'comment does not make a controller' => ['app/Services/Mailer.php', "<?php\n// extends Controller\nclass Mailer {}\n", 'other'],
]);

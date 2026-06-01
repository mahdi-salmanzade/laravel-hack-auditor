<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Scanner\AccessControl\UnauthorizedModelFetchDetector;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 */
function runFetchDetector(array $files): array
{
    $detector = new UnauthorizedModelFetchDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, new AccessControlContext);
}

function fetchController(string $methods): array
{
    return [[
        'path' => 'app/Http/Controllers/InvoiceController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Invoice;\nclass InvoiceController\n{\n{$methods}\n}\n",
    ]];
}

it('flags find by request id returned without authorization', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::find($request->id);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->line)->toBeGreaterThan(1)
        ->and($findings[0]->description)->toContain('show');
});

it('flags findOrFail with id from request via local variable', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $id = $request->input('id');
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor);
});

it('flags findOrFail with a typed route-param id and no authorization (M3 headline IDOR)', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('show');
});

it('flags an untyped route-param $id findOrFail returned without authorization (M3)', function (): void {
    $method = <<<'PHP'
        public function show($id)
        {
            $invoice = Invoice::findOrFail($id);
            return response()->json($invoice);
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::Idor);
});

it('does NOT flag a route-param findOrFail that is authorized (M3 safe)', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $this->authorize('view', $invoice);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag a route-param fetch scoped to the owner (M3 safe)', function (): void {
    $method = <<<'PHP'
        public function show(int $id)
        {
            $invoice = auth()->user()->invoices()->findOrFail($id);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag a route-param fetch that is never exposed (M3 conservative)', function (): void {
    $method = <<<'PHP'
        public function touch(int $id)
        {
            $invoice = Invoice::findOrFail($id);
            $invoice->touch();
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag a non-id scalar parameter fetch (M3 conservative)', function (): void {
    $method = <<<'PHP'
        public function lookup(string $slug)
        {
            $invoice = Invoice::findOrFail($slug);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('flags where id from request first without ownership', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::where('id', $request->id)->first();
            return view('invoices.show', compact('invoice'));
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toHaveCount(1);
});

it('does NOT flag when $this->authorize is called', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::findOrFail($request->id);
            $this->authorize('view', $invoice);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag when Gate::authorize guards the fetch', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::findOrFail($request->id);
            Gate::authorize('view', $invoice);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag when the query is scoped to the owner', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = Invoice::where('id', $request->id)->where('user_id', auth()->id())->first();
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag when fetched through the auth user relationship', function (): void {
    $method = <<<'PHP'
        public function show(Request $request)
        {
            $invoice = auth()->user()->invoices()->findOrFail($request->id);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag a fetch that is not exposed', function (): void {
    $method = <<<'PHP'
        public function touch(Request $request)
        {
            $invoice = Invoice::find($request->id);
            $invoice->touch();
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag fetches that do not use request input', function (): void {
    $method = <<<'PHP'
        public function index()
        {
            $invoice = Invoice::find(1);
            return $invoice;
        }
    PHP;

    $findings = runFetchDetector(fetchController($method));

    expect($findings)->toBeEmpty();
});

it('does NOT flag non-controller files', function (): void {
    $files = [[
        'path' => 'app/Models/Invoice.php',
        'type' => 'model',
        'content' => "<?php\nclass Invoice { public function show(\$r){ \$i = Invoice::find(\$r->id); return \$i; } }",
    ]];

    $findings = runFetchDetector($files);

    expect($findings)->toBeEmpty();
});

<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\SemanticContext;
use Mahdi\HackAuditor\Scanner\Php\TaintState;

function taintState(string $body, string $class = 'SubjectController'): TaintState
{
    $source = <<<PHP
    <?php

    namespace App\Http\Controllers;

    use App\Models\User;
    use Illuminate\Http\Request;

    class {$class}
    {
        public function act(Request \$request, User \$user, int \$id)
        {
    {$body}
        }
    }
    PHP;

    $context = SemanticContext::fromSourceFiles([
        ['path' => 'app/Http/Controllers/Subject.php', 'content' => $source, 'type' => 'controller'],
        [
            'path' => 'app/Models/User.php',
            'content' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass User extends Model {}\n",
            'type' => 'model',
        ],
    ]);

    $method = $context->classes()->find('App\Http\Controllers\\'.$class)?->method('act');

    expect($method)->not->toBeNull();

    return $context->taint()->track($method);
}

it('propagates taint from request input through an assignment', function (): void {
    $state = taintState(<<<'PHP'
            $url = $request->input('url');
            $trimmed = trim($url);
            $target = 'https://'.$trimmed;
    PHP);

    expect($state->isTainted('url'))->toBeTrue()
        ->and($state->isTainted('trimmed'))->toBeTrue()
        ->and($state->isTainted('target'))->toBeTrue()
        ->and($state->taintedVariables())->toContain('url', 'trimmed', 'target');
});

it('clears taint when a variable is reassigned from a trusted source', function (): void {
    $state = taintState(<<<'PHP'
            $url = $request->input('url');
            $first = $url;
            $url = config('services.partner.url');
            $second = $url;
    PHP);

    expect($state->isTainted('first'))->toBeTrue()
        ->and($state->isTainted('second'))->toBeFalse()
        ->and($state->at('second')?->isTrusted())->toBeTrue();
});

it('answers per-line, so the same variable can be tainted then trusted', function (): void {
    $state = taintState(<<<'PHP'
            $value = $request->input('q');
            $value = config('app.name');
    PHP);

    $history = $state->history('value');

    expect($history)->toHaveCount(2)
        ->and($state->isTainted('value', $history[0]['line']))->toBeTrue()
        ->and($state->isTainted('value', $history[1]['line']))->toBeFalse()
        ->and($state->isTainted('value'))->toBeFalse();
});

it('keeps taint through an appending assignment', function (): void {
    $state = taintState(<<<'PHP'
            $path = $request->input('path');
            $path .= '/index.html';
    PHP);

    expect($state->isTainted('path'))->toBeTrue();
});

it('seeds parameters from their declared types', function (): void {
    $state = taintState('        $noop = 1;');

    expect($state->at('request')?->isTrusted())->toBeTrue()
        ->and($state->at('user')?->isTrusted())->toBeTrue()
        ->and($state->at('id')?->isTainted())->toBeTrue();
});

it('does not taint a scalar parameter of a class that is not a controller', function (): void {
    $state = taintState('        $noop = $id;', 'SubjectService');

    expect($state->at('id')?->isTainted())->toBeFalse()
        ->and($state->at('id')?->isUnknown())->toBeTrue();
});

it('never taints the authenticated user object or anything read from it', function (): void {
    $state = taintState(<<<'PHP'
            $owner = $request->user();
            $email = $owner->email;
            $ip = $request->ip();
    PHP);

    expect($state->isTainted('owner'))->toBeFalse()
        ->and($state->isTainted('email'))->toBeFalse()
        ->and($state->isTainted('ip'))->toBeFalse()
        ->and($state->taintedVariables())->not->toContain('owner');
});

it('does not descend into a closure, whose variables are a different scope', function (): void {
    $state = taintState(<<<'PHP'
            $rows = collect([1, 2])->map(function ($row) use ($request) {
                $inner = $request->input('q');

                return $inner;
            });
    PHP);

    expect($state->final())->not->toHaveKey('inner');
});

it('marks a value whose origin it cannot explain as unknown rather than tainted', function (): void {
    $state = taintState(<<<'PHP'
            $row = $user->settings()->firstOrFail();
            $flag = $row->enabled;
    PHP);

    expect($state->at('row')?->isUnknown())->toBeTrue()
        ->and($state->isTainted('flag'))->toBeFalse();
});

it('reports validated input as tainted but flags that it passed validation', function (): void {
    $state = taintState('        $data = $request->validated();');

    expect($state->isTainted('data'))->toBeTrue()
        ->and($state->at('data')?->validated)->toBeTrue();
});

<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use Mahdi\HackAuditor\Scanner\Php\PolicyIndex;
use Mahdi\HackAuditor\Scanner\Php\PolicyInspector;

function policyCorpusIndex(): PolicyIndex
{
    $root = dirname(__DIR__).'/Fixtures/precision/app/Policies';
    $parser = new PhpAstParser;
    $files = [];

    foreach ((array) glob($root.'/*.php') as $path) {
        $files[] = $parser->parseFile((string) $path);
    }

    return PolicyIndex::fromFiles($files);
}

it('lists exactly the abilities a Policy declares', function (): void {
    expect(policyCorpusIndex()->abilitiesFor('Room'))->toBe([
        'view',
        'update',
        'delete',
        'manageImage',
        'managePassword',
        'manageTriggers',
        'manageWebhooks',
        'manageMembers',
        'viewPrivateLocation',
    ]);
});

it('knows a Policy exists yet declares no store and no create ability', function (): void {
    $index = policyCorpusIndex();

    expect($index->hasPolicyFor('Room'))->toBeTrue()
        ->and($index->hasAbility('Room', 'update'))->toBeTrue()
        ->and($index->hasAbility('Room', 'store'))->toBeFalse()
        ->and($index->hasAbility('Room', 'create'))->toBeFalse()
        ->and($index->hasAbility('Invoice', 'store'))->toBeFalse();
});

it('recognises an ability that IS declared, including on another policy', function (): void {
    $index = policyCorpusIndex();

    expect($index->hasAbility('Post', 'create'))->toBeTrue()
        ->and($index->hasAbility('Post', 'viewAny'))->toBeTrue()
        ->and($index->hasAbility('Post', 'store'))->toBeFalse();
});

it('resolves a policy by short name and by fully-qualified model name', function (): void {
    $index = policyCorpusIndex();

    expect($index->hasPolicyFor('App\Models\Room'))->toBeTrue()
        ->and($index->hasPolicyFor('Room'))->toBeTrue()
        ->and($index->hasPolicyFor('Article'))->toBeFalse();
});

it('derives the governed model from the ability signatures', function (): void {
    $parser = new PhpAstParser;
    $policy = $parser->parseFile(dirname(__DIR__).'/Fixtures/precision/app/Policies/RoomPolicy.php')->primaryClass();

    expect($policy)->not->toBeNull()
        ->and((new PolicyInspector)->modelFor($policy))->toBe('App\Models\Room');
});

it('ignores the before() hook when listing abilities', function (): void {
    $source = <<<'PHP'
    <?php

    namespace App\Policies;

    use App\Models\Ticket;
    use App\Models\User;

    class TicketPolicy
    {
        public function before(User $user, string $ability): ?bool
        {
            return $user->isAdmin() ? true : null;
        }

        public function view(User $user, Ticket $ticket): bool
        {
            return true;
        }

        protected function helper(): void {}
    }
    PHP;

    $policy = (new PhpAstParser)->parse('TicketPolicy.php', $source)->primaryClass();

    expect((new PolicyInspector)->abilities($policy))->toBe(['view'])
        ->and((new PolicyInspector)->modelFor($policy))->toBe('App\Models\Ticket');
});

it('cites the real line of an ability so advice can point at it', function (): void {
    $policy = (new PhpAstParser)
        ->parseFile(dirname(__DIR__).'/Fixtures/precision/app/Policies/RoomPolicy.php')
        ->primaryClass();

    $inspector = new PolicyInspector;
    $ability = $inspector->ability($policy, 'manageMembers');

    expect($ability)->not->toBeNull()
        ->and($ability->declarationLine())->toBeGreaterThan($policy->startLine())
        ->and($inspector->ability($policy, 'store'))->toBeNull();
});

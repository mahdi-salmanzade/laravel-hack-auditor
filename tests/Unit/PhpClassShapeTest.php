<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\Php\ClassShape;
use Mahdi\HackAuditor\Scanner\Php\PhpAstParser;
use Mahdi\HackAuditor\Scanner\Php\PropertyShape;

function shapeOf(string $source): ClassShape
{
    $class = (new PhpAstParser)->parse('Subject.php', $source)->primaryClass();

    expect($class)->not->toBeNull();

    return $class;
}

it('reports the exact line of the function keyword, not the docblock above it', function (): void {
    $source = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    class SubjectController
    {
        /**
         * A long docblock.
         *
         * Several lines of it.
         */
        public function store(): void
        {
        }
    }
    PHP;

    expect(shapeOf($source)->method('store')?->declarationLine())->toBe(12);
});

it('reports the function line for a multi-line signature and a default containing a paren', function (): void {
    $source = <<<'PHP'
    <?php

    class SubjectController
    {
        public function index(
            string $label = 'draft (pending)',
            int $perPage = 15,
        ): array {
            return [];
        }

        public function show(): void
        {
        }
    }
    PHP;

    $class = shapeOf($source);

    expect($class->method('index')?->declarationLine())->toBe(5)
        ->and($class->method('show')?->declarationLine())->toBe(12)
        ->and($class->method('index')?->parameter('label')?->hasDefault())->toBeTrue();
});

it('does not see methods that only exist in comments or strings', function (): void {
    $source = <<<'PHP'
    <?php

    class SubjectController
    {
        // public function legacyIndex(Request $request): JsonResponse
        // {
        //     return [];
        // }

        public function stub(): string
        {
            return 'public function handle(Request $request): void {';
        }
    }
    PHP;

    $names = array_map(
        static fn ($method): string => $method->name(),
        shapeOf($source)->publicMethods(),
    );

    expect($names)->toBe(['stub']);
});

it('excludes constructors, magic, static, private and abstract methods from public actions', function (): void {
    $source = <<<'PHP'
    <?php

    abstract class SubjectController
    {
        public function __construct() {}

        public function __invoke(): void {}

        public static function make(): self {}

        protected function guard(): void {}

        private function secret(): void {}

        abstract public function later(): void;

        public function action(): void {}
    }
    PHP;

    $names = array_map(
        static fn ($method): string => $method->name(),
        shapeOf($source)->publicMethods(),
    );

    expect($names)->toBe(['action']);
});

it('resolves constructor-promoted, typed and documented properties with their evidence', function (): void {
    $source = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Services\ImageUploadService;
    use GuzzleHttp\Client;

    class SubjectController
    {
        protected Client $http;

        /** @var \App\Support\Settings */
        protected $settings;

        protected $untyped;

        public function __construct(private readonly ImageUploadService $imageUpload) {}
    }
    PHP;

    $class = shapeOf($source);

    expect($class->propertyClass('imageUpload'))->toBe('App\Services\ImageUploadService')
        ->and($class->property('imageUpload')?->origin())->toBe(PropertyShape::ORIGIN_PROMOTED)
        ->and($class->property('imageUpload')?->visibility())->toBe('private')
        ->and($class->property('imageUpload')?->evidence())->toContain('constructor-promoted')
        ->and($class->propertyClass('http'))->toBe('GuzzleHttp\Client')
        ->and($class->property('http')?->origin())->toBe(PropertyShape::ORIGIN_DECLARED)
        ->and($class->propertyClass('settings'))->toBe('App\Support\Settings')
        ->and($class->property('settings')?->origin())->toBe(PropertyShape::ORIGIN_DOCBLOCK)
        ->and($class->property('untyped'))->toBeNull();
});

it('resolves parameter types from the signature and from @param when untyped', function (): void {
    $source = <<<'PHP'
    <?php

    namespace App\Http\Controllers;

    use App\Models\Room;
    use Illuminate\Http\Request;

    class SubjectController
    {
        /**
         * @param  \App\Support\Filter  $filter
         */
        public function index(Request $request, Room $room, int $page, $filter, ?string $q = null): void {}
    }
    PHP;

    $class = shapeOf($source);
    $method = $class->method('index');

    expect($method?->parameter('request')?->type())->toBe('Illuminate\Http\Request')
        ->and($method?->parameter('room')?->classType($class->file()))->toBe('App\Models\Room')
        ->and($method?->parameter('page')?->isScalar())->toBeTrue()
        ->and($method?->parameter('page')?->classType($class->file()))->toBeNull()
        ->and($method?->parameter('filter')?->isTyped())->toBeFalse()
        ->and($method?->parameter('filter')?->classType($class->file()))->toBe('App\Support\Filter')
        ->and($method?->parameter('q')?->isNullable())->toBeTrue()
        ->and($method?->parameter('q')?->isScalar())->toBeTrue();
});

it('reads ancestry so a subclass can be recognised', function (): void {
    $source = <<<'PHP'
    <?php

    namespace App\Models;

    use Illuminate\Foundation\Auth\User as Authenticatable;
    use Illuminate\Database\Eloquent\Concerns\HasUuids;

    class User extends Authenticatable implements \JsonSerializable
    {
        use HasUuids;
    }
    PHP;

    $class = shapeOf($source);

    expect($class->parentClass())->toBe('Illuminate\Foundation\Auth\User')
        ->and($class->interfaces())->toBe(['JsonSerializable'])
        ->and($class->traits())->toBe(['Illuminate\Database\Eloquent\Concerns\HasUuids']);
});

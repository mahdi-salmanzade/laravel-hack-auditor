<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Scanner\AccessControl\AccessControlContext;
use Mahdi\HackAuditor\Scanner\AccessControl\PolicyRouteMismatchDetector;
use Mahdi\HackAuditor\Scanner\AccessControl\SourceFile;
use Mahdi\HackAuditor\Support\SeverityLevel;
use Mahdi\HackAuditor\Support\VulnerabilityType;

/**
 * @param  array<int, array{path: string, content: string, type: string}>  $files
 */
function runPolicyDetector(array $files, AccessControlContext $context): array
{
    $detector = new PolicyRouteMismatchDetector;
    $sources = array_map(fn (array $f): SourceFile => SourceFile::fromArray($f), $files);

    return $detector->detect($sources, $context);
}

function policyController(string $methods): array
{
    return [[
        'path' => 'app/Http/Controllers/PostController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nclass PostController\n{\n{$methods}\n}\n",
    ]];
}

it('flags an update action when a Post policy exists but is never applied', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: ['Post']);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->type)->toBe(VulnerabilityType::AuthBypass)
        ->and($findings[0]->severity)->toBe(SeverityLevel::High)
        ->and($findings[0]->description)->toContain('Post')
        ->and($findings[0]->description)->toContain('update');
});

it('attributes to the controller-resource model when several models are touched (M4)', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $author = Author::find($request->author_id);
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: ['Post', 'Author']);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('Post')
        ->and($findings[0]->proof)->toContain('PostPolicy');
});

it('does NOT flag when attribution is ambiguous across two policied non-resource models (M4)', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $tag = Tag::find($request->tag_id);
            $category = Category::findOrFail($id);
            $tag->update($request->all());
            return $category;
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: ['Tag', 'Category']);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toBeEmpty();
});

it('attributes to the single policied model when only one of several touched models has a policy (M4)', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $tag = Tag::find($request->tag_id);
            $category = Category::findOrFail($id);
            $category->update($request->all());
            return $category;
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: ['Category']);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('Category');
});

it('flags a destroy action with an existing policy and no guard', function (): void {
    $method = <<<'PHP'
        public function destroy($id)
        {
            Post::destroy($id);
            return response()->noContent();
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: ['Post']);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toHaveCount(1);
});

it('does NOT flag when no policy exists for the model', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: []);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toBeEmpty();
});

it('does NOT flag when the method calls $this->authorize', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $this->authorize('update', $post);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: ['Post']);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toBeEmpty();
});

it('does NOT flag when the controller uses authorizeResource', function (): void {
    $controller = [[
        'path' => 'app/Http/Controllers/PostController.php',
        'type' => 'controller',
        'content' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\n".
            "class PostController\n{\n".
            "    public function __construct() { \$this->authorizeResource(Post::class, 'post'); }\n".
            "    public function update(Request \$request, \$id)\n    {\n        \$post = Post::findOrFail(\$id);\n        \$post->update(\$request->all());\n        return \$post;\n    }\n}\n",
    ]];

    $context = new AccessControlContext(modelsWithPolicy: ['Post']);
    $findings = runPolicyDetector($controller, $context);

    expect($findings)->toBeEmpty();
});

it('does NOT flag when the route carries can: middleware', function (): void {
    $method = <<<'PHP'
        public function update(Request $request, $id)
        {
            $post = Post::findOrFail($id);
            $post->update($request->all());
            return $post;
        }
    PHP;

    $context = new AccessControlContext(
        routedMethods: [
            'PostController@update' => ['route' => 'PUT /posts/{post}', 'middleware' => ['web', 'auth', 'can:update,post']],
        ],
        modelsWithPolicy: ['Post'],
    );

    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toBeEmpty();
});

it('does NOT flag non-sensitive read actions', function (): void {
    $method = <<<'PHP'
        public function index()
        {
            return Post::all();
        }
    PHP;

    $context = new AccessControlContext(modelsWithPolicy: ['Post']);
    $findings = runPolicyDetector(policyController($method), $context);

    expect($findings)->toBeEmpty();
});

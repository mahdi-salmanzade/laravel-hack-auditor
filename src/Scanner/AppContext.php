<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner;

final readonly class AppContext
{
    /**
     * Create a new AppContext instance.
     *
     * @param  array<string, array{method: string, uri: string, middleware: array<int, string>}>  $routes  Map of "ControllerClass@method" => route info
     * @param  array<string, string>  $middlewareDefinitions  Map of middleware alias => description
     * @param  array<int, string>  $globalMiddleware  List of global middleware class names
     * @param  array<string, string>  $rateLimiters  Map of limiter name => description
     * @param  array<string, array{policy: string, methods: array<int, string>}>  $policies  Map of model FQCN => policy info
     * @param  array<string, array{authorize: string, rules: array<string, string>}>  $formRequests  Map of FormRequest FQCN => info (authorize logic, rules)
     * @param  array<string, array{fillable: array<int, string>, hidden: array<int, string>, guarded: array<int, string>, casts: array<string, string>, traits: array<int, string>}>  $models  Map of model FQCN => info
     * @param  array<string, mixed>  $configContext  Security-relevant config (auth guards, cors, session, sanctum)
     * @param  array<string, array<int, string>>  $baseControllerMiddleware  Middleware from base controller constructors
     * @param  array<string, string>  $environment  APP_ENV, APP_DEBUG info
     */
    public function __construct(
        public array $routes,
        public array $middlewareDefinitions,
        public array $globalMiddleware,
        public array $rateLimiters,
        public array $policies,
        public array $formRequests,
        public array $models,
        public array $configContext,
        public array $baseControllerMiddleware,
        public array $environment,
    ) {}

    /**
     * Create an empty context with all arrays empty.
     */
    public static function empty(): self
    {
        return new self(
            routes: [],
            middlewareDefinitions: [],
            globalMiddleware: [],
            rateLimiters: [],
            policies: [],
            formRequests: [],
            models: [],
            configContext: [],
            baseControllerMiddleware: [],
            environment: [],
        );
    }

    /**
     * Serialize the context into a human-readable format for AI prompts.
     *
     * Only includes sections that contain data. Each section is formatted
     * concisely to minimize token usage while preserving useful detail.
     */
    public function toPromptString(): string
    {
        $sections = [];

        if ($this->environment !== []) {
            $lines = [];
            foreach ($this->environment as $key => $value) {
                $lines[] = "  {$key}: {$value}";
            }
            $sections[] = "## Environment\n".implode("\n", $lines);
        }

        if ($this->globalMiddleware !== []) {
            $sections[] = "## Global Middleware\n  ".implode(', ', $this->globalMiddleware);
        }

        if ($this->middlewareDefinitions !== []) {
            $lines = [];
            foreach ($this->middlewareDefinitions as $alias => $description) {
                $lines[] = "  {$alias} => {$description}";
            }
            $sections[] = "## Middleware Definitions\n".implode("\n", $lines);
        }

        if ($this->routes !== []) {
            $lines = [];
            foreach ($this->routes as $action => $info) {
                $middleware = $info['middleware'] ?? [];
                $mwStr = $middleware !== [] ? ' ['.implode(', ', $middleware).']' : '';
                $method = $info['method'] ?? 'GET';
                $uri = $info['uri'] ?? '/';
                $lines[] = "  {$action} => {$method} {$uri}{$mwStr}";
            }
            $sections[] = "## Routes\n".implode("\n", $lines);
        }

        if ($this->policies !== []) {
            $lines = [];
            foreach ($this->policies as $model => $info) {
                $policy = $info['policy'] ?? 'unknown';
                $methods = $info['methods'] ?? [];
                $methodStr = $methods !== [] ? ' (methods: '.implode(', ', $methods).')' : '';
                $lines[] = "  {$model} => {$policy}{$methodStr}";
            }
            $sections[] = "## Policies\n".implode("\n", $lines);
        }

        if ($this->formRequests !== []) {
            $lines = [];
            foreach ($this->formRequests as $fqcn => $info) {
                $authorize = $info['authorize'] ?? 'n/a';
                $rules = $info['rules'] ?? [];
                $rulesStr = $rules !== [] ? ', rules: ['.implode(', ', array_map(
                    fn (string $field, string $rule): string => "{$field} => {$rule}",
                    array_keys($rules),
                    array_values($rules),
                )).']' : '';
                $lines[] = "  {$fqcn} => authorize: {$authorize}{$rulesStr}";
            }
            $sections[] = "## Form Requests\n".implode("\n", $lines);
        }

        if ($this->models !== []) {
            $lines = [];
            foreach ($this->models as $fqcn => $info) {
                $parts = [];
                foreach (['fillable', 'hidden', 'guarded', 'casts', 'traits'] as $key) {
                    $values = $info[$key] ?? [];
                    if ($values !== []) {
                        if ($key === 'casts') {
                            $castStr = implode(', ', array_map(
                                fn (string $attr, string $type): string => "{$attr}:{$type}",
                                array_keys($values),
                                array_values($values),
                            ));
                            $parts[] = "{$key}: [{$castStr}]";
                        } else {
                            $parts[] = "{$key}: [".implode(', ', $values).']';
                        }
                    }
                }
                $lines[] = "  {$fqcn} => ".implode(', ', $parts);
            }
            $sections[] = "## Models\n".implode("\n", $lines);
        }

        if ($this->rateLimiters !== []) {
            $lines = [];
            foreach ($this->rateLimiters as $name => $description) {
                $lines[] = "  {$name} => {$description}";
            }
            $sections[] = "## Rate Limiters\n".implode("\n", $lines);
        }

        if ($this->baseControllerMiddleware !== []) {
            $lines = [];
            foreach ($this->baseControllerMiddleware as $controller => $middleware) {
                $lines[] = "  {$controller} => [".implode(', ', $middleware).']';
            }
            $sections[] = "## Base Controller Middleware\n".implode("\n", $lines);
        }

        if ($this->configContext !== []) {
            $sections[] = "## Security Config\n  ".json_encode($this->configContext, JSON_UNESCAPED_SLASHES);
        }

        if ($sections === []) {
            return '';
        }

        return "# Application Security Context\n\n".implode("\n\n", $sections);
    }

    /**
     * Estimate the token count of the prompt string (~4 chars per token).
     */
    public function estimateTokens(): int
    {
        return (int) ceil(strlen($this->toPromptString()) / 4);
    }

    /**
     * Return a new AppContext with data trimmed to fit within the token budget.
     *
     * Removes sections in priority order (least important first):
     * configContext, environment, baseControllerMiddleware, rateLimiters,
     * models, formRequests, policies, middlewareDefinitions, routes.
     * Routes are kept last as they are the most important.
     */
    public function truncateToTokenBudget(int $maxTokens): self
    {
        if ($this->estimateTokens() <= $maxTokens) {
            return $this;
        }

        $trimOrder = [
            'configContext',
            'environment',
            'baseControllerMiddleware',
            'rateLimiters',
            'models',
            'formRequests',
            'policies',
            'middlewareDefinitions',
            'routes',
        ];

        $data = [
            'routes' => $this->routes,
            'middlewareDefinitions' => $this->middlewareDefinitions,
            'globalMiddleware' => $this->globalMiddleware,
            'rateLimiters' => $this->rateLimiters,
            'policies' => $this->policies,
            'formRequests' => $this->formRequests,
            'models' => $this->models,
            'configContext' => $this->configContext,
            'baseControllerMiddleware' => $this->baseControllerMiddleware,
            'environment' => $this->environment,
        ];

        foreach ($trimOrder as $field) {
            $data[$field] = [];

            $candidate = new self(
                routes: $data['routes'],
                middlewareDefinitions: $data['middlewareDefinitions'],
                globalMiddleware: $data['globalMiddleware'],
                rateLimiters: $data['rateLimiters'],
                policies: $data['policies'],
                formRequests: $data['formRequests'],
                models: $data['models'],
                configContext: $data['configContext'],
                baseControllerMiddleware: $data['baseControllerMiddleware'],
                environment: $data['environment'],
            );

            if ($candidate->estimateTokens() <= $maxTokens) {
                return $candidate;
            }
        }

        return self::empty();
    }
}

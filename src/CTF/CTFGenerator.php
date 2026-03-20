<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\CTF;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Mahdi\HackAuditor\AI\AIAdapter;
use Mahdi\HackAuditor\AI\PromptBuilder;
use Mahdi\HackAuditor\Contracts\CTFGeneratorInterface;
use Mahdi\HackAuditor\Exceptions\InvalidAIResponseException;

final class CTFGenerator implements CTFGeneratorInterface
{
    /**
     * Create a new CTFGenerator instance.
     */
    public function __construct(
        private readonly AIAdapter $ai,
        private readonly PromptBuilder $promptBuilder,
    ) {}

    /**
     * Generate a Capture-The-Flag challenge based on a vulnerability type.
     *
     * Creates a complete CTF directory containing a README, challenge code,
     * solution, flag file, and Docker Compose setup. When source code is
     * provided, the AI tailors the challenge to the actual vulnerable code.
     *
     * @param  string  $vulnerabilityType  A VulnerabilityType enum value (snake_case)
     * @param  string|null  $sourceCode  Optional source code to base the challenge on
     * @return string The absolute path to the generated CTF directory
     *
     * @throws InvalidAIResponseException
     */
    public function generate(string $vulnerabilityType, ?string $sourceCode = null): string
    {
        $timestamp = now()->format('Ymd_His');
        $typeSlug = Str::snake($vulnerabilityType);
        $directoryName = "{$timestamp}_{$typeSlug}";

        /** @var string $outputBase */
        $outputBase = config('hack-auditor.ctf.output_path', 'storage/hack-auditor/ctf');
        $outputPath = storage_path($outputBase).'/'.$directoryName;

        File::ensureDirectoryExists($outputPath);

        $flag = $this->generateFlag($typeSlug);
        $challengeData = $this->generateChallengeData($vulnerabilityType, $flag, $sourceCode);

        $this->writeReadme($outputPath, $challengeData);
        $this->writeChallenge($outputPath, $challengeData);
        $this->writeSolution($outputPath, $challengeData);
        $this->writeFlag($outputPath, $flag);
        $this->writeDockerCompose($outputPath);

        return $outputPath;
    }

    /**
     * Generate a unique CTF flag string.
     */
    private function generateFlag(string $typeSnakeCase): string
    {
        $randomHex = bin2hex(random_bytes(3));

        return "FLAG{hack_auditor_{$typeSnakeCase}_{$randomHex}}";
    }

    /**
     * Generate challenge data using the AI adapter.
     *
     * @return array{title: string, difficulty: string, category: string, description: string, rules: string, hints: string, challenge_code: string, solution_explanation: string, fix_explanation: string}
     *
     * @throws InvalidAIResponseException
     */
    private function generateChallengeData(string $vulnerabilityType, string $flag, ?string $sourceCode): array
    {
        $systemPrompt = $this->promptBuilder->forCtfGeneration();

        $userPrompt = $sourceCode !== null
            ? $this->promptBuilder->ctfFromSourceCode($vulnerabilityType, $sourceCode, $flag)
            : $this->promptBuilder->ctfGeneric($vulnerabilityType, $flag);

        $response = $this->ai->ask($systemPrompt, $userPrompt);
        $json = $this->extractJson($response);

        /** @var array<string, mixed>|null $data */
        $data = json_decode($json, true);

        if (! is_array($data)) {
            throw InvalidAIResponseException::malformed('Failed to parse JSON', $response);
        }

        $requiredFields = [
            'title', 'difficulty', 'category', 'description',
            'rules', 'hints', 'challenge_code',
            'solution_explanation', 'fix_explanation',
        ];

        foreach ($requiredFields as $field) {
            if (! isset($data[$field]) || ! is_string($data[$field])) {
                throw InvalidAIResponseException::missingField($field);
            }
        }

        /** @var array{title: string, difficulty: string, category: string, description: string, rules: string, hints: string, challenge_code: string, solution_explanation: string, fix_explanation: string} $data */
        return $data;
    }

    /**
     * Extract a JSON block from a potentially markdown-wrapped AI response
     * and sanitize control characters that break json_decode.
     */
    private function extractJson(string $response): string
    {
        // Match the outermost code fence (greedy inner match to avoid
        // matching backtick blocks inside JSON string values).
        if (preg_match('/\A\s*```(?:json)?\s*([\s\S]*)```\s*\z/', $response, $matches)) {
            $json = trim($matches[1]);
        } else {
            $json = trim($response);
        }

        // If it parses cleanly, return as-is.
        if (json_decode($json, true) !== null) {
            return $json;
        }

        // AI sometimes puts literal newlines/tabs inside JSON string values.
        // Walk through the string tracking whether we're inside a quoted value
        // and escape only control characters found inside strings.
        $length = strlen($json);
        $result = '';
        $inString = false;
        $i = 0;

        while ($i < $length) {
            $char = $json[$i];

            if (! $inString) {
                if ($char === '"') {
                    $inString = true;
                }
                $result .= $char;
                $i++;

                continue;
            }

            // Inside a string
            if ($char === '\\' && $i + 1 < $length) {
                // Already-escaped sequence — keep both chars
                $result .= $char.$json[$i + 1];
                $i += 2;

                continue;
            }

            if ($char === '"') {
                $inString = false;
                $result .= $char;
                $i++;

                continue;
            }

            // Replace unescaped control characters
            $ord = ord($char);
            if ($ord < 32) {
                $result .= match ($char) {
                    "\n" => '\n',
                    "\r" => '\r',
                    "\t" => '\t',
                    default => sprintf('\u%04x', $ord),
                };
            } else {
                $result .= $char;
            }

            $i++;
        }

        return $result;
    }

    /**
     * Write the README.md file using the ctf-readme stub.
     *
     * @param  array{title: string, difficulty: string, category: string, description: string, rules: string, hints: string}  $data
     */
    private function writeReadme(string $outputPath, array $data): void
    {
        $stub = $this->loadStub('ctf-readme.stub');

        $content = str_replace(
            ['{{title}}', '{{difficulty}}', '{{category}}', '{{description}}', '{{rules}}', '{{hints}}'],
            [$data['title'], $data['difficulty'], $data['category'], $data['description'], $data['rules'], $data['hints']],
            $stub,
        );

        File::put("{$outputPath}/README.md", $content);
    }

    /**
     * Write the challenge.php file using the ctf-challenge stub.
     *
     * @param  array{title: string, difficulty: string, category: string, challenge_code: string}  $data
     */
    private function writeChallenge(string $outputPath, array $data): void
    {
        $stub = $this->loadStub('ctf-challenge.stub');

        $content = str_replace(
            ['{{title}}', '{{category}}', '{{difficulty}}', '{{code}}'],
            [$data['title'], $data['category'], $data['difficulty'], $data['challenge_code']],
            $stub,
        );

        File::put("{$outputPath}/challenge.php", $content);
    }

    /**
     * Write the solution.php file with exploitation and fix details.
     *
     * @param  array{title: string, category: string, solution_explanation: string, fix_explanation: string}  $data
     */
    private function writeSolution(string $outputPath, array $data): void
    {
        $solution = <<<PHP
        <?php
        /**
         * ============================================================
         *  SPOILER WARNING - CTF SOLUTION
         * ============================================================
         *
         * Challenge: {$data['title']}
         * Category:  {$data['category']}
         *
         * Do not read this file unless you have already attempted
         * the challenge or need the solution for educational purposes.
         * ============================================================
         */

        /*
         * HOW TO EXPLOIT
         * ==============
         *
         * {$data['solution_explanation']}
         */

        /*
         * HOW TO FIX
         * ==========
         *
         * {$data['fix_explanation']}
         */

        PHP;

        File::put("{$outputPath}/solution.php", $solution);
    }

    /**
     * Write the flag.txt file containing the generated flag.
     */
    private function writeFlag(string $outputPath, string $flag): void
    {
        File::put("{$outputPath}/flag.txt", $flag."\n");
    }

    /**
     * Write the docker-compose.yml file for a simple challenge environment.
     */
    private function writeDockerCompose(string $outputPath): void
    {
        $dockerCompose = <<<'YAML'
        version: "3.8"

        services:
          nginx:
            image: nginx:alpine
            ports:
              - "8080:80"
            volumes:
              - ./:/var/www/html
              - ./nginx.conf:/etc/nginx/conf.d/default.conf
            depends_on:
              - php

          php:
            image: php:8.2-fpm
            volumes:
              - ./:/var/www/html
            environment:
              - DB_HOST=mysql
              - DB_DATABASE=ctf_challenge
              - DB_USERNAME=ctf
              - DB_PASSWORD=ctf_secret

          mysql:
            image: mysql:8.0
            environment:
              MYSQL_ROOT_PASSWORD: root_secret
              MYSQL_DATABASE: ctf_challenge
              MYSQL_USER: ctf
              MYSQL_PASSWORD: ctf_secret
            ports:
              - "3306:3306"
        YAML;

        File::put("{$outputPath}/docker-compose.yml", $dockerCompose);
    }

    /**
     * Load a stub file from the package's resources/stubs directory.
     */
    private function loadStub(string $stubName): string
    {
        $path = dirname(__DIR__, 2).'/resources/stubs/'.$stubName;

        if (! File::exists($path)) {
            throw new \RuntimeException("Stub file not found: {$path}");
        }

        return File::get($path);
    }
}

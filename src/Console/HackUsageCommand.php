<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Console;

use Illuminate\Console\Command;
use Mahdi\HackAuditor\Support\UsageLog;

final class HackUsageCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'hack:usage
        {--days=30 : Show usage from the last N days}
        {--json : Output as JSON}
        {--clear : Clear the usage log}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'View AI token usage history and cost estimates';

    /**
     * Execute the console command.
     */
    public function handle(UsageLog $usageLog): int
    {
        if ($this->option('clear')) {
            $usageLog->clear();
            $this->components->info('Usage log cleared.');

            return self::SUCCESS;
        }

        if ($this->option('json')) {
            $this->line((string) json_encode($usageLog->summary(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

            return self::SUCCESS;
        }

        $days = (int) $this->option('days');
        $summary = $usageLog->summary();
        $entries = $usageLog->since(now()->subDays($days));

        $this->newLine();
        $this->line('  <options=bold>Token Usage Summary</>');
        $this->line('  <fg=gray>'.str_repeat("\u{2500}", 19).'</>');
        $this->newLine();

        $this->components->twoColumnDetail('Period', "Last {$days} days");
        $this->components->twoColumnDetail('Total Scans', (string) $summary['total_scans']);
        $this->components->twoColumnDetail(
            'Total Tokens',
            sprintf(
                '%s (%s prompt + %s completion)',
                number_format($summary['total_tokens']),
                number_format($summary['total_prompt_tokens']),
                number_format($summary['total_completion_tokens']),
            ),
        );
        $this->components->twoColumnDetail('Total AI Requests', (string) $summary['total_requests']);
        $this->components->twoColumnDetail('Estimated Cost', sprintf('$%.4f', $summary['total_cost_usd']));

        $this->newLine();

        if ($entries === []) {
            $this->components->info('No usage data recorded yet. Run hack:scan to start tracking.');

            return self::SUCCESS;
        }

        $rows = array_map(function (array $entry): array {
            $path = (string) ($entry['path'] ?? 'full scan');

            if (mb_strlen($path) > 20) {
                $path = mb_substr($path, 0, 17).'...';
            }

            $model = (string) ($entry['model'] ?? $entry['provider'] ?? 'unknown');

            if (mb_strlen($model) > 22) {
                $model = mb_substr($model, 0, 19).'...';
            }

            return [
                isset($entry['timestamp']) ? date('Y-m-d H:i', strtotime((string) $entry['timestamp'])) : 'N/A',
                $model,
                $path,
                number_format((int) ($entry['total_tokens'] ?? 0)),
                sprintf('$%.4f', (float) ($entry['estimated_cost_usd'] ?? 0.0)),
                isset($entry['score']) ? (string) $entry['score'].'/100' : 'N/A',
            ];
        }, $entries);

        $this->table(
            ['Date', 'Model', 'Path', 'Tokens', 'Cost', 'Score'],
            $rows,
        );

        return self::SUCCESS;
    }
}

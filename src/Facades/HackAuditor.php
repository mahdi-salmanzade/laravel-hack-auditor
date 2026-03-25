<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Facades;

use Illuminate\Support\Facades\Facade;
use Mahdi\HackAuditor\HackAuditorManager;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

/**
 * @method static VulnerabilityReport scan(?string $path = null, ?\Mahdi\HackAuditor\Support\UsageTracker $tracker = null)
 * @method static VulnerabilityReport scanCode(string $code)
 * @method static string generateCTF(string $type, ?string $code = null)
 * @method static int score()
 * @method static \Mahdi\HackAuditor\Support\ScanHistory history()
 * @method static string generateReport(\Mahdi\HackAuditor\Scanner\VulnerabilityReport $report, array $meta = [])
 *
 * @see HackAuditorManager
 */
final class HackAuditor extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return HackAuditorManager::class;
    }
}

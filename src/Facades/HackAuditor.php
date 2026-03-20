<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Facades;

use Illuminate\Support\Facades\Facade;
use Mahdi\HackAuditor\HackAuditorManager;
use Mahdi\HackAuditor\Scanner\VulnerabilityReport;

/**
 * @method static VulnerabilityReport scan(?string $path = null)
 * @method static VulnerabilityReport scanCode(string $code)
 * @method static string generateCTF(string $type, ?string $code = null)
 * @method static int score()
 *
 * @see \Mahdi\HackAuditor\HackAuditorManager
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

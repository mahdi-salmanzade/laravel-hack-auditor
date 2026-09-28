<?php

declare(strict_types=1);

use Mahdi\HackAuditor\Support\ConsoleText;
use Symfony\Component\Console\Formatter\OutputFormatter;

it('neutralises formatter tags and raw escape sequences', function (): void {
    $hostile = "Click <href=https://evil.example/x>docs</> \e]0;pwned\x07 <error>boom</error>\r\x9b";

    $formatted = (new OutputFormatter(true))->format(ConsoleText::clean($hostile));

    expect($formatted)->not->toContain("\e]8;;https://evil.example")
        ->not->toContain("\e]0;")
        ->not->toContain("\r")
        ->toContain('<href=https://evil.example/x>docs</>')
        ->toContain('<error>boom</error>');
});

it('keeps newlines and tabs and survives invalid UTF-8', function (): void {
    expect(ConsoleText::stripControlCharacters("a\n\tb"))->toBe("a\n\tb")
        ->and(ConsoleText::stripControlCharacters("caf\xE9 ok"))->toContain('ok');
});

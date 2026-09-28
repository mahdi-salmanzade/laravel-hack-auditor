<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Support;

use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * Makes untrusted text safe to print to a terminal.
 *
 * Finding text is written by an AI model that has just read attacker-shaped
 * source code, so it is untrusted input. Printed raw it can:
 *
 *  - carry Symfony formatter tags — `<href=https://evil.example>docs</>` turns
 *    into a clickable OSC 8 hyperlink, `<error>` restyles the output;
 *  - carry raw escape sequences — `ESC ] 0 ;` retitles the terminal, other
 *    sequences move the cursor, clear lines or hide text.
 *
 * Every piece of finding text a command prints goes through clean().
 */
final class ConsoleText
{
    /**
     * Strip control characters and escape formatter tags.
     */
    public static function clean(string $text): string
    {
        return OutputFormatter::escape(self::stripControlCharacters($text));
    }

    /**
     * Remove C0/C1 control characters (keeping \n and \t) and scrub invalid
     * UTF-8, which would otherwise make the /u regex fail and return nothing.
     */
    public static function stripControlCharacters(string $text): string
    {
        $scrubbed = mb_scrub($text, 'UTF-8');

        return (string) preg_replace('/[\x{00}-\x{08}\x{0B}-\x{1F}\x{7F}-\x{9F}]/u', '', $scrubbed);
    }
}

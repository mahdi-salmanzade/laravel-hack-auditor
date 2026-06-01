<?php

declare(strict_types=1);

use Laravel\Mcp\Facades\Mcp;
use Mahdi\HackAuditor\Mcp\HackAuditorMcpServer;

/*
|--------------------------------------------------------------------------
| Hack Auditor MCP Server
|--------------------------------------------------------------------------
|
| Registers the Hack Auditor as a local (stdio) MCP server so AI coding
| agents such as Claude Code and Cursor can invoke the scanner as tools.
| Start it with: php artisan mcp:start hack-auditor
|
*/

Mcp::local('hack-auditor', HackAuditorMcpServer::class);

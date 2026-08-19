<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Route manifest for the benchmark corpus
|--------------------------------------------------------------------------
|
| The benchmark corpus is a set of standalone fixture files. There is no
| application around them: no routes/web.php, no kernel, no Router. That
| absence is not neutral — it changes what the scanner is entitled to say.
|
| The access-control engine will not claim "an attacker can reach this record"
| unless it can name the entry point the attacker would use. When a host route
| table exists and does not mention a controller action, that action is
| UNREACHABLE and the engine stays silent. That rule is what took 191 false
| IDOR reports on 6,221 real files down to zero, and it must not be weakened.
|
| Applied to a corpus with no application around it, however, the same rule
| silently deleted the corpus: every sample resolved to 'unreachable' and the
| planted IDOR at samples/IdorController.php:14 stopped being credited. The
| accuracy gate went on reporting a score it was no longer measuring.
|
| This file is the fix. The corpus describes its OWN application — it declares
| the routes that expose each sample, exactly as a real app's route file would.
| The benchmark builds a Router from these entries and hands the scanner a
| RuntimeIntrospector backed by it, so the corpus is analysed as the
| self-contained application it is, with the reachability rule fully intact.
|
| Every controller sample MUST appear here. A sample with no entry is not
| "clean", it is UNMEASURED — BenchmarkCorpusTest fails when one is missing.
|
| Middleware is declared as a real route would declare it. Note that it is
| load-bearing: a middleware the engine cannot prove inert (e.g. `can:view,invoice`)
| makes the action unreachable again, which is correct behaviour, not a bug.
|
*/

return [
    'description' => 'Routes that expose the benchmark corpus samples. Names each sample controller action so the corpus is analysed as a routed application.',

    'routes' => [
        [
            'verb' => 'GET',
            'uri' => 'invoices/{id}',
            'action' => 'App\Http\Controllers\IdorController@show',
            'middleware' => ['web', 'auth'],
        ],
        [
            'verb' => 'DELETE',
            'uri' => 'users/{id}',
            'action' => 'App\Http\Controllers\BrokenAccessControlController@destroy',
            'middleware' => ['web', 'auth'],
        ],
        [
            'verb' => 'GET',
            'uri' => 'products/search',
            'action' => 'App\Http\Controllers\SqlInjectionController@search',
            'middleware' => ['web', 'auth'],
        ],
        [
            'verb' => 'GET',
            'uri' => 'greet',
            'action' => 'App\Http\Controllers\XssController@greet',
            'middleware' => ['web'],
        ],
        [
            'verb' => 'POST',
            'uri' => 'diagnostics/ping',
            'action' => 'App\Http\Controllers\CommandInjectionController@ping',
            'middleware' => ['web', 'auth'],
        ],
        [
            'verb' => 'POST',
            'uri' => 'link-preview',
            'action' => 'App\Http\Controllers\SsrfController@fetch',
            'middleware' => ['web', 'auth'],
        ],
        [
            'verb' => 'GET',
            'uri' => 'users/{id}/profile',
            'action' => 'App\Http\Controllers\SensitiveDataController@profile',
            'middleware' => ['web', 'auth'],
        ],
        [
            'verb' => 'POST',
            'uri' => 'posts',
            'action' => 'App\Http\Controllers\CleanController@store',
            'middleware' => ['web', 'auth'],
        ],
    ],
];

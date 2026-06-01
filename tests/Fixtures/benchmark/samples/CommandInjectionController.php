<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class CommandInjectionController extends Controller
{
    public function ping(Request $request)
    {
        $host = $request->input('host');

        $output = shell_exec('ping -c 1 '.$host);

        return response($output);
    }
}

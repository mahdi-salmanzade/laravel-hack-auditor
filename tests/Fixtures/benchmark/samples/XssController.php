<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class XssController extends Controller
{
    public function greet(Request $request)
    {
        $name = $request->input('name');

        return response("<h1>Welcome back, {$name}!</h1>");
    }
}

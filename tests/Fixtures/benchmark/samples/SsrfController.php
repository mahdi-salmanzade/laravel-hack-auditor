<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class SsrfController extends Controller
{
    public function fetch(Request $request)
    {
        $url = $request->input('url');

        $response = Http::get($url);

        return response($response->body());
    }
}

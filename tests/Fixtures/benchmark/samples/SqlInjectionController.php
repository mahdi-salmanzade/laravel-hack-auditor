<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SqlInjectionController extends Controller
{
    public function search(Request $request)
    {
        $term = $request->query('q');

        $results = DB::select("SELECT * FROM products WHERE name LIKE '%{$term}%'");

        return response()->json($results);
    }
}

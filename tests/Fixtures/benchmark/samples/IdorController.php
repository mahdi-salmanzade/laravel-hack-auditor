<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;

class IdorController extends Controller
{
    public function show(Request $request, int $id)
    {
        $invoice = Invoice::findOrFail($id);

        return response()->json($invoice);
    }
}

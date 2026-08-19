<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\UpdateInvoiceRequest;
use App\Models\Invoice;
use Illuminate\Http\RedirectResponse;

/**
 * Authorisation lives on the route: `->middleware('can:update,invoice')`.
 * InvoicePolicy::update() is applied by the framework before this method runs.
 */
class InvoiceController extends Controller
{
    public function update(UpdateInvoiceRequest $request, string $number): RedirectResponse
    {
        $invoice = Invoice::where('number', $number)->firstOrFail();

        $invoice->update($request->validated());

        return redirect()->route('invoices.show', $invoice);
    }
}

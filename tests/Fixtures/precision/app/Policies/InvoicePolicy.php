<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Invoice;
use App\Models\User;

class InvoicePolicy
{
    public function view(User $user, Invoice $invoice): bool
    {
        return $invoice->customer_id === $user->id;
    }

    public function update(User $user, Invoice $invoice): bool
    {
        return $invoice->customer_id === $user->id && $invoice->isDraft();
    }

    public function delete(User $user, Invoice $invoice): bool
    {
        return $invoice->customer_id === $user->id && $invoice->isDraft();
    }
}

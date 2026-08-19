<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    /**
     * @var array<int, string>
     */
    protected $fillable = [
        'number',
        'notes',
        'due_on',
    ];

    public function isDraft(): bool
    {
        return $this->issued_at === null;
    }
}

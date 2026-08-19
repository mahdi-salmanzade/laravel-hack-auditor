<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MaintenanceWindow extends Model
{
    /**
     * @var array<int, string>
     */
    protected $fillable = [
        'label',
        'starts_at',
        'ends_at',
    ];
}

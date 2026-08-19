<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RoomReport extends Model
{
    /**
     * @var array<int, string>
     */
    protected $fillable = [
        'reason',
    ];
}

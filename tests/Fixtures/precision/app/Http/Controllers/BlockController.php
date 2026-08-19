<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\BlockUserRequest;
use App\Models\User;
use Illuminate\Http\JsonResponse;

/**
 * FALSE POSITIVE 5.
 *
 * `User::query()->whereIn(...)->lockForUpdate()->get()` is a database read, and
 * `$participants->get($blockedId)` is a Collection lookup by key. Neither is an
 * outbound request; there is no URL and no HTTP client in this file.
 */
class BlockController extends Controller
{
    public function store(BlockUserRequest $request): JsonResponse
    {
        $blockedId = (int) $request->validated('user_id');

        $participants = User::query()
            ->whereIn('id', [$request->user()->id, $blockedId])
            ->lockForUpdate()
            ->get()
            ->keyBy('id');

        $blocked = $participants->get($blockedId);

        abort_if($blocked === null, 404);

        $request->user()->blockedUsers()->syncWithoutDetaching([$blocked->id]);

        return response()->json(['blocked' => true], 201);
    }
}

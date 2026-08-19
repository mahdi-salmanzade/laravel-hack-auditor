<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\JoinRoomRequest;
use App\Models\Room;
use Illuminate\Http\JsonResponse;

/**
 * FALSE POSITIVE 2.
 *
 * Joining a room is authorised by possession of the invite code plus an
 * authenticated session. RoomPolicy declares manageMembers — which governs an
 * OWNER changing someone else's membership — and no ability that covers a user
 * joining by code. Nothing is bypassed.
 */
class RoomMemberController extends Controller
{
    public function store(JoinRoomRequest $request): JsonResponse
    {
        $room = Room::where('invite_code', $request->validated('invite_code'))->firstOrFail();

        $room->members()->syncWithoutDetaching([$request->user()->id]);

        return response()->json(['joined' => true], 201);
    }
}

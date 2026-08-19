<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\StoreRoomRequest;
use App\Http\Requests\UpdateRoomRequest;
use App\Models\Room;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;

/**
 * FALSE POSITIVE 1.
 *
 * store() creates a Room. A RoomPolicy exists, but it declares no `store` and
 * no `create` ability — creating a room needs an authenticated session and
 * nothing more, which the route's `auth` middleware enforces. There is no
 * policy to apply here and therefore nothing to bypass.
 *
 * The suggested remedy that shipped with the original finding —
 * `$this->authorize('store', $room)` at the top of store() — would fatal:
 * `$room` does not exist yet, and RoomPolicy has no `store` method.
 */
class RoomController extends Controller
{
    public function store(StoreRoomRequest $request): JsonResponse
    {
        $room = Room::create([
            'name' => $request->validated('name'),
            'slug' => Str::slug($request->validated('name')),
            'description' => $request->validated('description'),
            'capacity' => $request->validated('capacity'),
            'invite_code' => Str::random(12),
        ]);

        $room->owner()->associate($request->user());
        $room->save();

        return response()->json(['id' => $room->id], 201);
    }

    /**
     * update() DOES have a matching ability, and applies it.
     */
    public function update(UpdateRoomRequest $request, Room $room): JsonResponse
    {
        $this->authorize('update', $room);

        $room->update($request->validated());

        return response()->json(['updated' => true]);
    }
}

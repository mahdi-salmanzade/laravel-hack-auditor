<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\ReportRoomRequest;
use App\Models\Room;
use Illuminate\Http\JsonResponse;

/**
 * FALSE POSITIVE 3.
 *
 * Any authenticated user may report any room for abuse — that is the entire
 * point of an abuse report. RoomPolicy declares no `report` and no `store`
 * ability, so there is no policy for this action to apply.
 */
class RoomReportController extends Controller
{
    public function store(ReportRoomRequest $request): JsonResponse
    {
        $room = Room::findOrFail($request->validated('room_id'));

        $room->reports()->create([
            'reason' => $request->validated('reason'),
            'reported_by' => $request->user()->id,
        ]);

        return response()->json(['reported' => true], 202);
    }
}

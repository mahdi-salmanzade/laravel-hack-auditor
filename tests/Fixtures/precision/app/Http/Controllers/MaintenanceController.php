<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\MaintenanceWindow;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * LINE PRECISION.
 *
 * Every shape that breaks a signature-matching regex lives here: leading
 * docblocks, a multi-line signature, a default value containing a `)`, a nested
 * closure, and a commented-out method that still looks like a declaration.
 *
 * A reported line must land on the `function` keyword of a method that really
 * exists — never inside a docblock, never inside a comment, never in a
 * different method.
 */
class MaintenanceController extends Controller
{
    /**
     * List the maintenance windows for one label.
     *
     * @param  string  $label  Display label, e.g. "draft (pending)"
     */
    public function index(
        Request $request,
        string $label = 'draft (pending)',
    ): JsonResponse {
        $windows = MaintenanceWindow::query()
            ->where('label', $label)
            ->orderBy('starts_at')
            ->get()
            ->map(function (MaintenanceWindow $window): array {
                return [
                    'id' => $window->id,
                    'label' => $window->label,
                    'starts_at' => $window->starts_at?->toIso8601String(),
                ];
            });

        return response()->json(['data' => $windows, 'page' => $request->integer('page', 1)]);
    }

    // Removed in v3. Kept here while API clients migrate:
    // public function legacyIndex(Request $request): JsonResponse
    // {
    //     return response()->json(MaintenanceWindow::all());
    // }

    /**
     * Show a single window.
     */
    public function show(MaintenanceWindow $window): JsonResponse
    {
        return response()->json($window->only(['id', 'label']));
    }
}

<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class BrokenAccessControlController extends Controller
{
    public function destroy(Request $request, int $id)
    {
        $user = User::findOrFail($id);

        $user->delete();

        return response()->json(['deleted' => true]);
    }
}

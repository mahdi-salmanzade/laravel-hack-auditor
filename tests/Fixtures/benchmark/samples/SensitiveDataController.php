<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\User;

class SensitiveDataController extends Controller
{
    public function profile(int $id)
    {
        $user = User::findOrFail($id);

        return response()->json([
            'name' => $user->name,
            'email' => $user->email,
            'password_hash' => $user->password,
            'remember_token' => $user->remember_token,
            'api_secret' => $user->api_secret,
        ]);
    }
}

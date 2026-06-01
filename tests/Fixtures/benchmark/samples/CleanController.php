<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\StorePostRequest;
use Illuminate\Support\Facades\Auth;

class CleanController extends Controller
{
    public function store(StorePostRequest $request)
    {
        $post = Auth::user()->posts()->create($request->validated());

        return response()->json(['id' => $post->id], 201);
    }
}

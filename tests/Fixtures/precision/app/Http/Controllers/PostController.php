<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/**
 * Ordinary resource controller. Every action is authorised by
 * authorizeResource(), which maps the CRUD verbs onto PostPolicy.
 */
class PostController extends Controller
{
    public function __construct()
    {
        $this->authorizeResource(Post::class, 'post');
    }

    public function index(): View
    {
        return view('posts.index', [
            'posts' => Post::query()->latest()->paginate(15),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'title' => ['required', 'string', 'max:255'],
            'body' => ['required', 'string'],
        ]);

        $post = $request->user()->posts()->create($data);

        return redirect()->route('posts.show', $post);
    }

    public function show(Post $post): View
    {
        return view('posts.show', ['post' => $post]);
    }

    public function update(Request $request, Post $post): RedirectResponse
    {
        $post->update($request->validate([
            'title' => ['sometimes', 'string', 'max:255'],
            'body' => ['sometimes', 'string'],
        ]));

        return redirect()->route('posts.show', $post);
    }

    public function destroy(Post $post): RedirectResponse
    {
        $post->delete();

        return redirect()->route('posts.index');
    }
}

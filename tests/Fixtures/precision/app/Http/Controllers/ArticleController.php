<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\StoreArticleRequest;
use App\Models\Article;
use Illuminate\Http\RedirectResponse;

/**
 * Validated input plus configuration reads. There is no ArticlePolicy, so
 * there is no policy to enforce and nothing to report.
 */
class ArticleController extends Controller
{
    public function store(StoreArticleRequest $request): RedirectResponse
    {
        $wordsPerMinute = (int) config('articles.words_per_minute', 220);

        $article = Article::create([
            ...$request->validated(),
            'reading_time' => (int) ceil(str_word_count($request->validated('body')) / $wordsPerMinute),
        ]);

        $article->author()->associate($request->user());
        $article->save();

        return redirect()->route('articles.show', $article);
    }
}

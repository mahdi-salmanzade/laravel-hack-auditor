<?php

declare(strict_types=1);

use App\Http\Controllers\ArticleController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\BlockController;
use App\Http\Controllers\InvoiceController;
use App\Http\Controllers\MaintenanceController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\RoomController;
use App\Http\Controllers\RoomMemberController;
use App\Http\Controllers\RoomReportController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group(function (): void {
    Route::post('/rooms', [RoomController::class, 'store'])->name('rooms.store');
    Route::put('/rooms/{room}', [RoomController::class, 'update'])->name('rooms.update');
    Route::post('/rooms/join', [RoomMemberController::class, 'store'])->name('rooms.join');
    Route::post('/rooms/reports', [RoomReportController::class, 'store'])->name('rooms.reports.store');

    Route::delete('/profile/image', [AuthController::class, 'deleteProfileImage'])->name('profile.image.destroy');
    Route::post('/profile/image', [AuthController::class, 'updateProfileImage'])->name('profile.image.update');

    Route::post('/blocks', [BlockController::class, 'store'])->name('blocks.store');
    Route::post('/articles', [ArticleController::class, 'store'])->name('articles.store');

    Route::put('/invoices/{invoice}', [InvoiceController::class, 'update'])
        ->middleware('can:update,invoice')
        ->name('invoices.update');
});

Route::resource('posts', PostController::class);

Route::get('/maintenance', [MaintenanceController::class, 'index'])->name('maintenance.index');
Route::get('/maintenance/{window}', [MaintenanceController::class, 'show'])->name('maintenance.show');

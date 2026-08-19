<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\UpdateProfileImageRequest;
use App\Services\ImageUploadService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * FALSE POSITIVE 4.
 *
 * Neither method makes an outbound request. `$this->imageUpload` is a
 * constructor-promoted ImageUploadService — local disk storage — and
 * `$request->user()` is the AUTHENTICATED USER OBJECT, not attacker-controlled
 * input. There is no HTTP client anywhere in this file.
 */
class AuthController extends Controller
{
    public function __construct(private readonly ImageUploadService $imageUpload) {}

    /**
     * Remove the authenticated user's profile image.
     */
    public function deleteProfileImage(Request $request): JsonResponse
    {
        $user = $request->user();

        $this->imageUpload->delete($user->profile_image);

        $user->forceFill(['profile_image' => null])->save();

        return response()->json(['message' => __('profile.image_removed')]);
    }

    /**
     * Replace the authenticated user's profile image.
     */
    public function updateProfileImage(UpdateProfileImageRequest $request): JsonResponse
    {
        $this->imageUpload->delete($request->user()->profile_image);

        $path = $this->imageUpload->store($request->file('image'), 'avatars');

        $request->user()->forceFill(['profile_image' => $path])->save();

        return response()->json(['profile_image' => $path]);
    }
}

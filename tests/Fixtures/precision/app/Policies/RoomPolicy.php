<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Room;
use App\Models\User;

/**
 * Abilities defined for Room.
 *
 * There is deliberately no `store` and no `create` ability: creating a room
 * requires nothing but an authenticated session, which the `auth` middleware
 * already enforces. Nothing here can be "bypassed" by a create action.
 */
class RoomPolicy
{
    public function view(User $user, Room $room): bool
    {
        return $room->is_public || $room->members()->whereKey($user->id)->exists();
    }

    public function update(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }

    public function delete(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }

    public function manageImage(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }

    public function managePassword(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }

    public function manageTriggers(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }

    public function manageWebhooks(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }

    public function manageMembers(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }

    public function viewPrivateLocation(User $user, Room $room): bool
    {
        return $room->owner_id === $user->id;
    }
}

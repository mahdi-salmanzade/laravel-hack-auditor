<?php

declare(strict_types=1);

namespace Mahdi\HackAuditor\Scanner\Php;

/**
 * What a call's receiver actually is.
 *
 * `Unknown` is the default and is not a soft "maybe dangerous" — it means the
 * code did not tell us, so no detector may act on the call.
 */
enum ReceiverKind: string
{
    /** Illuminate Http facade / PendingRequest / Guzzle / PSR-18 client. */
    case HttpClient = 'http_client';

    /** Eloquent model, Eloquent or query builder, relation, or the DB facade. */
    case Eloquent = 'eloquent';

    /** Illuminate Support/Eloquent Collection. */
    case Collection = 'collection';

    /** The filesystem: Storage facade or a Filesystem contract. */
    case Storage = 'storage';

    /** The current HTTP request object. */
    case Request = 'request';

    /** A concrete application class injected into the caller. */
    case LocalService = 'local_service';

    /** No type declaration reaches the receiver. */
    case Unknown = 'unknown';

    public function isOutboundHttp(): bool
    {
        return $this === self::HttpClient;
    }

    public function label(): string
    {
        return match ($this) {
            self::HttpClient => 'an outbound HTTP client',
            self::Eloquent => 'an Eloquent model or query builder',
            self::Collection => 'a Collection',
            self::Storage => 'the filesystem',
            self::Request => 'the HTTP request',
            self::LocalService => 'a local application service',
            self::Unknown => 'an unresolved receiver',
        };
    }
}

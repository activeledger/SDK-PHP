<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * Anything that can sign transaction bytes and name its key type.
 *
 * An interface rather than a concrete type so a caller can sign elsewhere --
 * an HSM, a remote signing service, a key in a user's wallet -- without this
 * SDK needing to know about it.
 */
interface Signer
{
    public function keyType(): KeyType;

    /** The public key, base64, in the encoding the ledger stores. */
    public function publicKeyBase64(): string;

    /**
     * Signs the canonical bytes of a `$tx` object, returning the raw
     * signature. The caller base64-encodes it for `$sigs`.
     */
    public function sign(string $message): string;
}

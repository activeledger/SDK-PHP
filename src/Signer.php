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

    /**
     * The public key, as the string the ledger stores.
     *
     * The encoding depends on the scheme, which is why this is not named for
     * one: post-quantum keys are base64, and secp256k1 keys are 0x-prefixed
     * hex. Whatever this returns goes into the transaction verbatim.
     */
    public function publicKey(): string;

    /**
     * Signs the canonical bytes of a `$tx` object, returning the raw
     * signature. The caller base64-encodes it for `$sigs`.
     */
    public function sign(string $message): string;
}

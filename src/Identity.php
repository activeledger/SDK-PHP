<?php

declare(strict_types=1);

namespace Activeledger;

/** An onboarded identity: its stream id and the key controlling it. */
final class Identity
{
    public function __construct(
        public readonly string $streamId,
        public readonly Signer $signer,
    ) {
    }

    public function publicKey(): string
    {
        return $this->signer->publicKey();
    }
}

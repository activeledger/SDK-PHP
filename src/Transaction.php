<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * A signed transaction, ready to submit.
 *
 * The body is the `$tx` object. `$sigs` maps a signer label to a base64
 * signature over the canonical bytes of the body and NOTHING ELSE -- not the
 * envelope, not a hash of it, not a length-prefixed form.
 */
final class Transaction
{
    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $sigs
     */
    public function __construct(
        private readonly array $body,
        private readonly array $sigs,
        private readonly bool $selfSign,
    ) {
    }

    /** The `$tx` object. These are the bytes that get signed. */
    public function body(): array
    {
        return $this->body;
    }

    /** @return array<string, string> */
    public function sigs(): array
    {
        return $this->sigs;
    }

    public function isSelfSigned(): bool
    {
        return $this->selfSign;
    }

    /** The full envelope, as submitted. */
    public function envelope(): array
    {
        $envelope = ['$tx' => $this->body];

        if ($this->selfSign) {
            $envelope['$selfsign'] = true;
        }

        $envelope['$sigs'] = CanonicalJson::object($this->sigs);

        return $envelope;
    }

    /** The envelope serialised for submission. */
    public function toJson(): string
    {
        return CanonicalJson::encode($this->envelope());
    }

    /** The exact bytes that were signed. The fastest way to diagnose a 1220. */
    public function signedBytes(): string
    {
        return CanonicalJson::bytes($this->body);
    }

    /**
     * Builds the onboarding transaction for a new identity.
     *
     * Two things here are the most common first failure in any port, so they
     * happen in one place rather than being left to a caller: `$selfsign` is
     * true and `$sigs` is keyed by the `$i` LABEL rather than a stream id
     * (there is no stream yet); and `type` is always present, because the
     * ledger defaults a missing one to `rsa` and then attempts RSA
     * verification against a base64 post-quantum blob.
     */
    public static function onboard(Signer $signer, string $label = 'identity'): self
    {
        $body = [
            '$namespace' => 'default',
            '$contract' => 'onboard',
            '$i' => [
                $label => [
                    'type' => $signer->keyType()->value,
                    'publicKey' => $signer->publicKeyBase64(),
                ],
            ],
            // Must serialise as {} rather than [].
            '$o' => CanonicalJson::object(),
        ];

        $signature = base64_encode($signer->sign(CanonicalJson::bytes($body)));

        return new self($body, [$label => $signature], true);
    }

    public static function builder(): TransactionBuilder
    {
        return new TransactionBuilder();
    }
}

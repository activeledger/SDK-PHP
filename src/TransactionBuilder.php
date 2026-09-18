<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * Builds an ordinary transaction.
 *
 * Insertion order is preserved throughout, because the ledger does not
 * canonicalise key order and the signature covers the order actually written.
 */
final class TransactionBuilder
{
    private ?string $namespace = null;
    private ?string $contract = null;
    private ?string $entry = null;

    /** @var array<string, mixed> */
    private array $inputs = [];

    /** @var array<string, mixed> */
    private array $outputs = [];

    /** @var array<string, string> */
    private array $readonly = [];

    /** @var array<string, Signer> */
    private array $signers = [];

    public function namespace(string $value): self
    {
        $this->namespace = $value;
        return $this;
    }

    public function contract(string $value): self
    {
        $this->contract = $value;
        return $this;
    }

    /** Sets `$entry`, the contract entry point. Omitted when not set. */
    public function entry(string $value): self
    {
        $this->entry = $value;
        return $this;
    }

    /**
     * Adds an input stream, its signing key and any payload fields.
     *
     * @param array<string, mixed> $payload
     */
    public function input(string $streamId, Signer $signer, array $payload = []): self
    {
        $this->inputs[$streamId] = $payload === [] ? CanonicalJson::object() : $payload;
        $this->signers[$streamId] = $signer;
        return $this;
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function output(string $streamId, array $payload = []): self
    {
        $this->outputs[$streamId] = $payload === [] ? CanonicalJson::object() : $payload;
        return $this;
    }

    /**
     * Adds a stream to `$r`, the read-only set.
     *
     * This is how state is read from Activeledger. There is no separate read
     * API: a node's storage service listens only on its own host, so reading
     * is a transaction like anything else. The contract receives the named
     * streams and hands values back with `returnToRemote`.
     */
    public function readonly(string $label, string $streamId): self
    {
        $this->readonly[$label] = $streamId;
        return $this;
    }

    /**
     * Signs and returns the transaction.
     *
     * @throws \LogicException when namespace, contract or any input is missing
     */
    public function build(): Transaction
    {
        if ($this->namespace === null) {
            throw new \LogicException('namespace is required');
        }
        if ($this->contract === null) {
            throw new \LogicException('contract is required');
        }
        if ($this->signers === []) {
            throw new \LogicException('at least one input with a signing key is required');
        }

        $body = [];
        if ($this->entry !== null) {
            $body['$entry'] = $this->entry;
        }
        $body['$namespace'] = $this->namespace;
        $body['$contract'] = $this->contract;
        $body['$i'] = $this->inputs;

        if ($this->outputs !== []) {
            $body['$o'] = $this->outputs;
        }
        if ($this->readonly !== []) {
            $body['$r'] = $this->readonly;
        }

        $message = CanonicalJson::bytes($body);

        $sigs = [];
        foreach ($this->signers as $label => $signer) {
            $sigs[$label] = base64_encode($signer->sign($message));
        }

        return new Transaction($body, $sigs, false);
    }
}

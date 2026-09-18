<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * A connection to one Activeledger node.
 */
final class Client
{
    private readonly string $baseUrl;
    private readonly ?string $coreUrl;

    /**
     * @param string $baseUrl The node's transaction URL, e.g. http://localhost:5260
     * @param string|null $coreUrl The Activecore URL, which serves the event
     *        streams. Activecore is a SEPARATE service on its own port, not a
     *        path on the node: a node answers 403 for every event route, so
     *        defaulting this to $baseUrl would turn a missing Activecore into
     *        a puzzling permissions error. Leave it null unless subscribing.
     */
    public function __construct(
        string $baseUrl,
        ?string $coreUrl = null,
        private readonly int $timeoutSeconds = 30,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->coreUrl = $coreUrl === null ? null : rtrim($coreUrl, '/');
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    public function coreUrl(): ?string
    {
        return $this->coreUrl;
    }

    public function submit(Transaction $transaction): LedgerResponse
    {
        return $this->submitRaw($transaction->toJson());
    }

    /**
     * Submits a pre-built envelope.
     *
     * For envelopes built elsewhere, and for testing rejection paths -- a
     * tampered body cannot be expressed through submit(), because the builder
     * would re-sign it into a valid transaction.
     *
     * @throws \RuntimeException on a transport failure
     */
    public function submitRaw(string $body): LedgerResponse
    {
        $handle = curl_init($this->baseUrl . '/');
        if ($handle === false) {
            throw new \RuntimeException('Could not initialise curl');
        }

        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
        ]);

        $raw = curl_exec($handle);
        $error = curl_error($handle);
        // No curl_close(): the handle is an object freed by refcount, the
        // function has had no effect since PHP 8.0, and calling it is
        // deprecated from 8.5.
        unset($handle);

        if ($raw === false) {
            throw new \RuntimeException("Request to {$this->baseUrl} failed: $error");
        }

        return new LedgerResponse((string) $raw);
    }

    /**
     * Onboards a new identity.
     *
     * Throws if the ledger rejected it, rather than returning an Identity with
     * an empty stream id -- an onboarding that silently produced no identity
     * is a failure that surfaces three calls later.
     *
     * @throws \RuntimeException
     */
    public function onboard(Signer $signer): Identity
    {
        $response = $this->submit(Transaction::onboard($signer));

        $streams = $response->newStreams();
        if ($streams === []) {
            throw new \RuntimeException('Onboard failed: ' . $response->raw());
        }

        return new Identity($streams[0], $signer);
    }

    /**
     * Subscribes to activity: every stream change on the ledger, or the
     * changes to one stream.
     *
     * This is the feed that fires for ordinary transactions. Contract events
     * are a different feed carrying only what a contract explicitly emitted,
     * so a subscriber watching there sees nothing for a transaction that
     * emitted no event -- which looks exactly like a broken subscription.
     *
     * @param callable(LedgerEvent): (bool|null) $onEvent Return false to stop.
     * @throws \LogicException when no Activecore URL was configured
     */
    public function subscribeToActivity(callable $onEvent, ?string $streamId = null): void
    {
        $path = $streamId === null
            ? '/api/activity/subscribe'
            : '/api/activity/subscribe/' . rawurlencode($streamId);

        $this->subscribe($this->requireCore() . $path, $onEvent);
    }

    /**
     * Subscribes to events emitted by contracts: all of them, those from one
     * contract, or one named event from one contract.
     *
     * @param callable(LedgerEvent): (bool|null) $onEvent Return false to stop.
     * @throws \LogicException
     */
    public function subscribeToContractEvents(
        callable $onEvent,
        ?string $contract = null,
        ?string $eventName = null,
    ): void {
        if ($contract === null && $eventName !== null) {
            throw new \LogicException('An event name needs the contract it belongs to');
        }

        $path = '/api/events';
        if ($contract !== null) {
            $path .= '/' . rawurlencode($contract);
        }
        if ($eventName !== null) {
            $path .= '/' . rawurlencode($eventName);
        }

        $this->subscribe($this->requireCore() . $path, $onEvent);
    }

    /**
     * Subscribes to an arbitrary path or absolute URL.
     *
     * Blocks until the callback returns false, the server closes the stream or
     * the timeout expires.
     *
     * @param callable(LedgerEvent): (bool|null) $onEvent Return false to stop.
     * @throws \RuntimeException
     */
    public function subscribe(string $pathOrUrl, callable $onEvent, ?int $timeoutSeconds = null): void
    {
        $target = str_starts_with($pathOrUrl, 'http://') || str_starts_with($pathOrUrl, 'https://')
            ? $pathOrUrl
            : $this->baseUrl . $pathOrUrl;

        $handle = curl_init($target);
        if ($handle === false) {
            throw new \RuntimeException('Could not initialise curl');
        }

        $parser = new EventParser();
        $stopped = false;

        curl_setopt_array($handle, [
            CURLOPT_HTTPHEADER => ['Accept: text/event-stream', 'Cache-Control: no-cache'],
            CURLOPT_TIMEOUT => $timeoutSeconds ?? 0,
            CURLOPT_WRITEFUNCTION => function ($_, string $chunk) use ($parser, $onEvent, &$stopped): int {
                $length = strlen($chunk);

                foreach ($parser->push($chunk) as $event) {
                    if ($onEvent($event) === false) {
                        $stopped = true;
                        // Returning anything other than the chunk length aborts
                        // the transfer, which is how the connection is closed.
                        return 0;
                    }
                }

                return $length;
            },
        ]);

        $ok = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        $errno = curl_errno($handle);
        // See submitRaw(): curl_close() is a deprecated no-op.
        unset($handle);

        // Without this a rejected subscription becomes an empty event stream:
        // the caller waits for events that were never coming, and nothing
        // anywhere reports a problem. Pointing a subscription at a node
        // instead of Activecore returns 403, and that is worth being told.
        if ($status !== 0 && $status >= 400) {
            throw new \RuntimeException(
                "Subscription to $target was rejected with HTTP $status"
            );
        }

        // A requested timeout expiring is how a subscription ENDS, not how it
        // fails. An event stream is meant to stay open with nothing to say, so
        // curl always finishes one by timing out -- reporting that as an error
        // would make every well-behaved subscription look broken.
        $timedOutAsAsked = $errno === CURLE_OPERATION_TIMEOUTED
            && $timeoutSeconds !== null
            && $timeoutSeconds > 0;

        if ($ok === false && !$stopped && !$timedOutAsAsked && $error !== '') {
            throw new \RuntimeException("Subscription to $target failed: $error");
        }

        if (!$stopped) {
            $final = $parser->finish();
            if ($final !== null) {
                $onEvent($final);
            }
        }
    }

    private function requireCore(): string
    {
        return $this->coreUrl ?? throw new \LogicException(
            'No Activecore URL was configured. Event streams are served by '
            . 'Activecore, a separate service from the node - pass it as the '
            . 'second constructor argument.'
        );
    }
}

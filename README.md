<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger - PHP SDK

Build, sign and submit Activeledger transactions from PHP, with post-quantum
identities.

- **ML-DSA-65** post-quantum identities, verified against the ledger's
  published cross-language vectors
- Canonical JSON that reproduces the exact bytes the ledger signs
- Transaction builder, client and server-sent event subscriptions
- Pure PHP — no extension required, no native library to install

## Read this first: private keys are not portable

**An identity created by another Activeledger SDK cannot be used here, and an
identity created here cannot have its private key loaded elsewhere.**

The underlying library (`paragonie/pqcrypto_compat`) implements FIPS 204 key
generation from a **32-byte seed**, but not private key encoding or decoding.
The JavaScript, JVM, C#, Go and Rust SDKs all store the **4032-byte** private
key. There is no conversion in that direction, because the 4032-byte form
cannot be turned back into the seed it came from.

What still works everywhere:

| | Works |
|---|---|
| Verify any ledger signature | ✅ public keys are the standard 1952-byte encoding |
| Onboard an identity created here | ✅ the ledger sees a normal `ml-dsa-65` identity |
| Sign transactions | ✅ standard 3309-byte signatures, hedged |
| Reuse an identity created here, in PHP | ✅ store `seedBase64()` |
| Load a private key from another SDK | ❌ throws, by design |
| Hand a PHP private key to another SDK | ❌ it is a seed, not a 4032-byte key |

Passing a 4032-byte key throws immediately with an explanation. That guard
exists because the library underneath **does not** reject it: it accepts any
string as seed material, derives a completely unrelated identity, and signs
happily. Those signatures are then rejected by the ledger as 1220 "Signature
Incorrect" — a message that points nowhere near the cause.

If you need one identity shared between PHP and another language, generate it
in PHP and give the other SDK only the public key, or use one of the other
SDKs for signing.

## Install

```bash
composer require activeledger/sdk
```

Requires PHP 8.1+ with `ext-curl` and `ext-json`. Installing the optional
`ext-pqcrypto` extension makes signing faster; the library picks it up
automatically.

## Quick start

```php
use Activeledger\Client;
use Activeledger\KeyPair;
use Activeledger\Transaction;

$client = new Client('http://localhost:5260');

// A post-quantum identity
$key = KeyPair::generate();
$identity = $client->onboard($key);

echo $identity->streamId;

// Store this to reuse the identity later. It is all you need, and it is
// the ONLY thing that will restore it.
file_put_contents('identity.seed', $key->seedBase64());

// A transaction signed by it
$tx = Transaction::builder()
    ->namespace('default')
    ->contract('mycontract')
    ->input($identity->streamId, $key, ['amount' => 100])
    ->output('someotherstream')
    ->build();

$response = $client->submit($tx);

if (!$response->committed()) {
    // NOT the HTTP status. See "A rejected transaction is an HTTP 200" below.
    print_r($response->errors());
}
```

Restoring that identity on a later request:

```php
$key = KeyPair::fromSeedBase64(file_get_contents('identity.seed'));
```

## Keys

```php
$key = KeyPair::generate();

$key->publicKeyBase64();   // 1952 bytes, exactly as the ledger stores it
$key->seedBase64();        // 32 bytes - store this
$key->canSign();           // true

// Verification only
$verifier = KeyPair::fromPublicKeyBase64($publicKey);
$verifier->verify($message, $signature);   // bool
```

**Signing is hedged**, not deterministic: fresh entropy goes into every
signature, so signing the same message twice produces different bytes. This
matches the reference implementation. Never compare signatures for equality —
verify them.

Performance, measured on a pure-PHP 8.4 build with no extension: key
generation ~28 ms, signing ~68 ms, verification ~27 ms.

## Transactions

```php
$tx = Transaction::builder()
    ->namespace('default')
    ->contract('mycontract')
    ->entry('transfer')                        // optional
    ->input($streamId, $key, ['amount' => 100])
    ->output($otherStream)                     // optional
    ->readonly('label', $someStreamId)         // optional, see "Reading state"
    ->build();
```

Every signer signs the *same* bytes: the canonical form of `$tx`. `$sigs` is
keyed by input stream id.

Onboarding differs in two ways that catch every port, so it has its own
constructor — `$selfsign` is true, and `$sigs` is keyed by the `$i` label
because no stream exists yet:

```php
$tx = Transaction::onboard($key);
```

To inspect exactly what was signed — the fastest way to diagnose a rejected
signature:

```php
$tx->signedBytes();   // the $tx object alone
$tx->toJson();        // the full envelope, as submitted
```

## Reading state

There is no read API. A node's storage service listens only on that node's own
host, so reading state is a transaction like any other: name the streams in
`$r`, and the contract hands values back with `returnToRemote`.

```php
$tx = Transaction::builder()
    ->namespace('default')
    ->contract('mycontract')
    ->entry('read')
    ->input($identity->streamId, $key)
    ->readonly('target', $streamToRead)
    ->build();

foreach ($client->submit($tx)->responses() as $value) {
    echo $value['balance'];
}
```

`$response->newStreams()` gives the ids of any streams the transaction created.

## Events (SSE)

Event streams are served by **Activecore**, which is a separate service on its
own port — not a path on the node. Pointing a subscription at a node returns
403, so the URL is supplied separately and subscribing without it throws a
message naming the missing URL rather than quietly producing an empty stream.

```php
use Activeledger\LedgerEvent;

$client = new Client('http://localhost:5260', 'http://localhost:5261');

// Every stream change on the ledger. Return false from the callback to stop.
$client->subscribeToActivity(function (LedgerEvent $event): bool {
    echo $event->data;
    return true;
});

// Changes to one stream
$client->subscribeToActivity($callback, $streamId);

// Events a contract emitted: all, by contract, or one named event
$client->subscribeToContractEvents($callback);
$client->subscribeToContractEvents($callback, 'mycontract');
$client->subscribeToContractEvents($callback, 'mycontract', 'transfer');
```

**Activity and contract events are different feeds.** Activity fires for stream
changes, so it is what an ordinary transaction produces. Contract events carry
only what a contract explicitly emitted — subscribe there for a transaction
that emits nothing and you will correctly receive nothing, which looks exactly
like a broken subscription.

Each `LedgerEvent` has `data`, plus `name` and `id` when the server sent them,
and `json()` to decode the payload. Multiple `data:` lines join with newlines,
and `:` heartbeat comments are ignored rather than delivered as empty events.

Subscribing blocks. Return `false` from the callback to close the connection,
or pass a timeout in seconds to `subscribe()` — a timeout expiring is a normal
end to a subscription, not an error.

## Signing elsewhere

`Signer` is all the SDK needs, so keys can live in an HSM, a remote signing
service or a user's wallet — and it is also the way to sign with a key this
SDK cannot load itself:

```php
use Activeledger\KeyType;
use Activeledger\Signer;

final class HsmSigner implements Signer
{
    public function keyType(): KeyType
    {
        return KeyType::MlDsa65;
    }

    public function publicKeyBase64(): string
    {
        // ...
    }

    public function sign(string $message): string
    {
        // ...
    }
}
```

`sign()` receives the canonical bytes of `$tx` and returns a raw signature; the
SDK base64-encodes it.

## Things that will bite you

**A rejected transaction is an HTTP 200.** The ledger answers 200 and reports
the problem in the body. Check `$response->committed()` — code that treats the
HTTP status as success will report commits that never happened, and will keep
doing so until something downstream notices the data is missing.

**Every signature problem is reported as 1220 "Signature Incorrect".** A wrong
key type, a missing `type`, wrong key material and genuinely bad bytes all
produce that one message. `$tx->signedBytes()` is usually the quickest way in.

**A missing `type` defaults to `rsa`.** The ledger then tries RSA verification
against whatever it was given. This SDK always sends the type explicitly.

**Namespaces are claimed permanently.** A test that registers a fixed namespace
passes once and fails every re-run against the same network, which reads like a
regression and is not one.

**Consensus is a majority.** When a submission returns, most nodes have
committed and the rest may still be writing. Reading immediately from a
specific node is a race.

## Canonical JSON

Signatures cover the exact bytes of `JSON.stringify($tx)` encoded as UTF-8 — no
hash prefix, no length prefix, no domain separator and **no key sorting**. A
signature over bytes that differ by a single escape is invalid.

PHP's `json_encode` cannot produce these bytes. By default it escapes forward
slashes as `\/` — and every base64 public key is full of them — and non-ASCII
as `\uXXXX`. So this SDK has its own serialiser:

```php
use Activeledger\CanonicalJson;

$json  = CanonicalJson::encode(['zebra' => 1, 'alpha' => 'text']);
$bytes = CanonicalJson::bytes(['zebra' => 1, 'alpha' => 'text']);
```

PHP arrays preserve insertion order, and that order is what gets signed.

One PHP-specific trap: `[]` is both an empty array and an empty object, and
`$o` in a transaction must serialise as `{}`. Use `CanonicalJson::object()`
where an object is required — the transaction builder already does.

```php
CanonicalJson::encode(['$o' => []]);                        // {"$o":[]}  wrong
CanonicalJson::encode(['$o' => CanonicalJson::object()]);   // {"$o":{}}  right
```

Numbers follow JavaScript: whole values print without a fractional part, so
`1.0` serialises as `1`. `NAN` and `INF` are refused rather than silently
written as `null`.

## Testing

```bash
composer install
vendor/bin/phpunit --testsuite unit
```

The live-network tests need a ledger. Start one from an `activeledger`
checkout:

```bash
npm run test:network:serve
```

then run with the URLs it prints:

```bash
AL_NODES=http://127.0.0.1:5510,http://127.0.0.1:5520 \
AL_STORAGE=http://127.0.0.1:5509,http://127.0.0.1:5519 \
vendor/bin/phpunit --testsuite live
```

They onboard real post-quantum identities, verify what the ledger actually
recorded on every node, confirm a tampered payload is rejected, check that an
identity restored from its seed still controls its stream, and open a real
event stream.

## Migrating from 1.x

Version 2 is a rewrite. The old lowercase classes are gone and the package is
PSR-4 under `Activeledger\`.

| 1.x | 2.x |
|---|---|
| `activeledger\key` | `Activeledger\KeyPair` |
| `activeledger\transaction` | `Activeledger\Transaction::builder()` |
| `activeledger\connection` | `Activeledger\Client` |

RSA and EC key generation are not carried over; identities created by this SDK
are post-quantum. `Signer` is available for anything else.

## Licence

MIT

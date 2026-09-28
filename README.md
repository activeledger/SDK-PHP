<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23-dark.png">
  <img src="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23.png" alt="Activeledger" width="300"/>
</picture>

[![Packagist](https://img.shields.io/packagist/v/activeledger/sdk)](https://packagist.org/packages/activeledger/sdk)
[![PHP](https://img.shields.io/packagist/dependency-v/activeledger/sdk/php)](https://packagist.org/packages/activeledger/sdk)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](https://github.com/activeledger/SDK-PHP/blob/master/LICENSE)

# Activeledger - PHP SDK

Build, sign and submit Activeledger transactions from PHP, with post-quantum
identities.

- **ML-DSA-65** post-quantum identities, verified against the ledger's
  published cross-language vectors
- Canonical JSON that reproduces the exact bytes the ledger signs
- Transaction builder, client and server-sent event subscriptions
- Pure PHP — no extension required, no native library to install

## Read this first: the seed is the portable private key

**A private key here is a 32-byte seed, not the 4032-byte encoding the other
SDKs export.** `paragonie/pqcrypto_compat` implements FIPS 204 key generation
from a seed, but not `skEncode`/`skDecode`, so the 4032-byte form cannot be
loaded here and cannot be turned back into the seed it came from.

That used to make an identity unmovable in either direction. It no longer
does — **every Activeledger SDK can now import a seed** — but the direction
matters:

| | Works |
|---|---|
| Verify any ledger signature | ✅ public keys are the standard 1952-byte encoding |
| Onboard an identity created here | ✅ the ledger sees a normal `ml-dsa-65` identity |
| Sign transactions | ✅ standard 3309-byte signatures, hedged |
| Reuse an identity created here, in PHP | ✅ store `seedBase64()` |
| Take a PHP identity to another SDK | ✅ give it the **seed**, via that SDK's `fromSeed` |
| Recover the same identity in both from one phrase | ✅ see [Recovery phrases](#recovery-phrases) |
| Load another SDK's **4032-byte** private key here | ❌ throws, by design |

So share the seed, never the 4032-byte key. The same 32 bytes derive an
identical 1952-byte public key in every SDK — verified against the JavaScript
implementation byte for byte.

Passing a 4032-byte key throws immediately with an explanation. That guard
exists because the library underneath **does not** reject it: it accepts any
string as seed material, derives a completely unrelated identity, and signs
happily. Those signatures are then rejected by the ledger as 1220 "Signature
Incorrect" — a message that points nowhere near the cause.

## Seeds and recovery phrases

### From a seed

```php
use Activeledger\KeyPair;
use Activeledger\Secp256k1KeyPair;

$pq = KeyPair::fromSeed($seed);                  // 32 bytes
$ec = Secp256k1KeyPair::fromSeed($seed);         // 32 bytes
```

A seed of the wrong length is **refused, not padded** — a padded seed is a
different identity, not a malformed one.

For `secp256k1` the seed **is** the private scalar, so it has to be a valid
one. A seed of zero, or one at or above the curve order, is refused rather
than reduced mod *n*: reducing produces a perfectly functional key belonging
to a different identity, and nothing downstream ever reports a problem.

### Recovery phrases

```php
$pq = KeyPair::fromPhrase($phrase);                    // ml-dsa-65
$ec = Secp256k1KeyPair::fromPhrase($phrase);           // secp256k1
$withPassphrase = KeyPair::fromPhrase($phrase, "...");
```

One phrase backs both identity types at once, because each derives its own
seed:

| Type | Seed from the BIP-39 seed `S` |
| --- | --- |
| `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
| `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |
| `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |

`secp256k1` deliberately does not use HKDF: the JavaScript SDK shipped that
derivation before the post-quantum types existed, so phrases are already in
use, and changing it would hand those users a different key for a phrase that
used to work. `Secp256k1KeyPair::fromLegacyPhrase()` recovers a phrase made
by the older `@activeledger/sdk-bip39` package — for recovery only, never for
new keys.

**The phrase is validated**, wordlist and checksum both. A mistyped phrase
that is not checked does not fail; it derives a perfectly valid key for an
identity nobody owns, and the only symptom is the ledger not recognising it.

`ext-intl` is optional and only affects non-ASCII passphrases, which BIP-39
requires to be NFKD-normalised.

## Key types

| Key type | Wire string | Public | Private | Signature | Encoding |
|---|---|---|---|---|---|
| ML-DSA-65 | `ml-dsa-65` | 1952 | 32-byte seed | 3309 | base64 |
| secp256k1 | `secp256k1` | 33 or 65 | 32 | ~70-72, variable | `0x` hex |

Use **secp256k1** unless the identity must outlive a cryptographically
relevant quantum computer: roughly **22x smaller** per transaction, and every
byte is stored on the ledger permanently and replicated to every node. It also
works with hardware wallets and HSMs, is the only way to sign for an identity
created before post-quantum support — and, unlike ML-DSA here, **its private
keys are portable to and from every other Activeledger SDK**.

```php
use Activeledger\Secp256k1KeyPair;

$key = Secp256k1KeyPair::generate();                      // compressed
$full = Secp256k1KeyPair::generate(compressed: false);    // uncompressed

$key->publicKey();    // "0x02a1b2..." - give this to the ledger
$key->privateKey();   // store this; it works in any SDK

$restored = Secp256k1KeyPair::fromKeys($key->publicKey(), $key->privateKey());
$verifier = Secp256k1KeyPair::fromPublicKey($key->publicKey());
```

secp256k1 uses `ext-openssl`, which is enabled in virtually every PHP build
and is **the same implementation the ledger verifies with** — so interop is
structural rather than hopeful. No Composer package, and no `ext-gmp` (which
`simplito/elliptic-php` requires outright).

### Encoded nothing like the post-quantum keys

- **Keys are `0x`-prefixed hex, not base64.** The prefix is required rather
  than tolerated, because hex without it can decode as base64 into
  plausible-looking bytes of the wrong length.
- **Public keys have two valid lengths**, 33 compressed and 65 uncompressed,
  and the ledger accepts both. A length and a SEC1 point prefix that disagree
  are rejected by name.
- **Private scalars are always 32 bytes**, left-padded.
- **Signatures are SHA-256 → ECDSA → DER**, and DER length varies.

### low-S, in both directions

**Signing always emits low-S.** OpenSSL does not normalise, so this SDK folds
S itself. Not for the ledger, which accepts either, but for `@noble/curves` —
the reference for the JavaScript side — and for libsecp256k1 and Rust's
`k256`, all of which reject high-S by default. A signer emitting high-S
roughly half the time fails against those roughly half the time, which reads
as flakiness rather than as a signature format problem.

**Verification accepts high-S**, because the ledger produces it freely.
Rejecting those would fail on roughly half of all valid signatures.

### One difference from the other SDKs

**Signing is not deterministic here.** OpenSSL uses a random k and offers no
way to inject one, so unlike the JavaScript, JVM, C#, Go and Rust SDKs this
one cannot reproduce the published RFC 6979 reference bytes — signing the same
message twice gives different bytes.

That costs a test, not correctness: everything it emits is a valid, canonical,
low-S signature that the ledger and every other SDK accept, and the suite
verifies the published deterministic signatures even though it cannot
reproduce them. Implementing RFC 6979 in PHP would mean hand-rolling 256-bit
modular arithmetic and point multiplication, which is a far worse trade.

## Install

```bash
composer require activeledger/sdk
```

Verified: resolves `activeledger/sdk (v2.3.0)` from Packagist with
`paragonie/pqcrypto_compat` and `paragonie/sodium_compat`, on PHP 8.5.


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

## Events (SSE) - deprecated

`Client::subscribeToActivity`, `subscribeToContractEvents` and `subscribe` are **deprecated** and will be removed in the next major version.

Events are no longer served by ActiveCore, which is itself deprecated and
should not be used. A node serves contract events from its own storage
service at `http://localhost:<storage port>/activeledgerevents/events`, and
that service must never be reachable beyond the node's host - so a client
SDK has nothing it should connect to.

To react to events, run your own server-sent events listener on the node's
host and relay what your application needs through your own backend. Each
event is an SSE frame whose `id` is `<milliseconds>-<counter>,<umid>` and
whose `data` is `{"name", "data", "phase", "contract"}`.

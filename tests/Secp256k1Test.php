<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\KeyType;
use Activeledger\Secp256k1KeyPair;
use PHPUnit\Framework\TestCase;

/**
 * secp256k1 conformance against the published cross-language vectors.
 *
 * Its encoding has nothing in common with the post-quantum schemes, and every
 * test here exists because reusing the base64 path produces material the
 * ledger rejects as 1220 "Signature Incorrect" while saying nothing else.
 *
 * One test the other SDKs have is deliberately absent: byte-exactness against
 * the published `deterministicSignature`. PHP signs through OpenSSL, which
 * uses a random k and offers no way to inject one, so this SDK is not RFC 6979
 * deterministic. Everything it emits is still a valid low-S signature the
 * ledger and every other SDK accept; it simply cannot be compared byte for
 * byte. `testSigningIsNotDeterministicAndThatIsDocumented` states that rather
 * than leaving it to be discovered.
 */
final class Secp256k1Test extends TestCase
{
    /** @return list<array<string, string>> */
    private function vectors(): array
    {
        return array_values(array_filter(
            Vectors::all(),
            static fn(array $v): bool => $v['type'] === 'secp256k1'
        ));
    }

    public function testBothPublicKeyFormsArePresent(): void
    {
        // The ledger accepts either, so a port that only ever sees one never
        // learns to read the other.
        $forms = array_unique(array_column($this->vectors(), 'publicKeyForm'));

        self::assertContains('compressed', $forms);
        self::assertContains('uncompressed', $forms);
        self::assertGreaterThanOrEqual(12, count($this->vectors()));
    }

    public function testVerifiesEveryPublishedSignature(): void
    {
        foreach ($this->vectors() as $v) {
            $key = Secp256k1KeyPair::fromPublicKey($v['publicKey']);

            self::assertTrue(
                $key->verify($v['message'], base64_decode($v['signature'])),
                "failed to verify secp256k1/{$v['messageName']}/{$v['publicKeyForm']}"
            );
        }
    }

    /**
     * High-S signatures must still verify.
     *
     * The ledger verifies through OpenSSL, which neither normalises nor
     * requires low-S, so it produces high-S freely. libsecp256k1 and Rust's
     * k256 both reject high-S by default; PHP's OpenSSL does not, which is
     * exactly why it is used here. A verifier enforcing low-S would reject
     * roughly half of everything the ledger makes, and the half that
     * succeeded would look like an intermittent fault rather than a crypto
     * one.
     */
    public function testHighSSignaturesFromElsewhereStillVerify(): void
    {
        foreach ($this->vectors() as $v) {
            $signature = base64_decode($v['highSSignature']);

            // The fixture must be what it claims. A "high-S" signature that is
            // not high-S would pass a permissive verifier for the wrong
            // reason: green, and proving nothing.
            self::assertTrue(
                Secp256k1KeyPair::isHighS($signature),
                "{$v['messageName']}/{$v['publicKeyForm']}: the published fixture is not high-S"
            );

            $key = Secp256k1KeyPair::fromPublicKey($v['publicKey']);
            self::assertTrue(
                $key->verify($v['message'], $signature),
                "rejected a high-S signature ({$v['messageName']}/{$v['publicKeyForm']}) "
                . '- low-S is being enforced on verify'
            );
        }
    }

    /**
     * Permissive about s only. Accepting high-S must not have quietly widened
     * anything else.
     */
    public function testTheHighSFormStillRejectsATamperedMessage(): void
    {
        foreach ($this->vectors() as $v) {
            $key = Secp256k1KeyPair::fromPublicKey($v['publicKey']);

            self::assertFalse(
                $key->verify($v['message'] . ' ', base64_decode($v['highSSignature']))
            );
        }
    }

    public function testEverySignatureEmittedIsLowS(): void
    {
        $key = Secp256k1KeyPair::generate();

        for ($i = 0; $i < 100; $i++) {
            self::assertFalse(
                Secp256k1KeyPair::isHighS($key->sign("message $i")),
                "signature $i was high-S"
            );
        }
    }

    /**
     * Stated rather than discovered.
     *
     * OpenSSL uses a random k, so this SDK cannot reproduce the published
     * deterministic bytes the way the other five can. If PHP ever grows a
     * usable RFC 6979 path this test will fail, which is the right prompt to
     * revisit it.
     */
    public function testSigningIsNotDeterministicAndThatIsDocumented(): void
    {
        $v = $this->vectors()[0];
        $key = Secp256k1KeyPair::fromKeys($v['publicKey'], $v['privateKey']);

        $first = $key->sign($v['message']);
        $second = $key->sign($v['message']);

        self::assertNotSame($first, $second, 'signing became deterministic - revisit the docs');

        // Both are still valid, and both are low-S.
        self::assertTrue($key->verify($v['message'], $first));
        self::assertTrue($key->verify($v['message'], $second));
        self::assertFalse(Secp256k1KeyPair::isHighS($first));
        self::assertFalse(Secp256k1KeyPair::isHighS($second));
    }

    /**
     * The published deterministic signatures must still VERIFY here, even
     * though this SDK cannot reproduce them. That is the half of
     * cross-language agreement PHP can prove.
     */
    public function testThePublishedDeterministicSignaturesVerify(): void
    {
        foreach ($this->vectors() as $v) {
            $key = Secp256k1KeyPair::fromPublicKey($v['publicKey']);

            self::assertTrue(
                $key->verify($v['message'], base64_decode($v['deterministicSignature'])),
                "rejected the reference deterministic signature ({$v['messageName']})"
            );
        }
    }

    public function testSignaturesMadeHereVerifyWithTheReferencePublicKey(): void
    {
        foreach ($this->vectors() as $v) {
            $signer = Secp256k1KeyPair::fromKeys($v['publicKey'], $v['privateKey']);
            $verifier = Secp256k1KeyPair::fromPublicKey($v['publicKey']);

            self::assertTrue(
                $verifier->verify($v['message'], $signer->sign($v['message'])),
                "reference key rejected a signature made here ({$v['messageName']})"
            );
        }
    }

    public function testRoundTripsPublishedKeysExactly(): void
    {
        foreach ($this->vectors() as $v) {
            $key = Secp256k1KeyPair::fromKeys($v['publicKey'], $v['privateKey']);

            self::assertSame($v['publicKey'], $key->publicKey());
            self::assertSame($v['privateKey'], $key->privateKey());
        }
    }

    public function testTamperedMessageDoesNotVerify(): void
    {
        foreach ($this->vectors() as $v) {
            $key = Secp256k1KeyPair::fromPublicKey($v['publicKey']);

            self::assertFalse(
                $key->verify($v['message'] . ' ', base64_decode($v['signature']))
            );
        }
    }

    public function testGeneratedKeysUseTheLedgersEncoding(): void
    {
        $key = Secp256k1KeyPair::generate();

        self::assertStringStartsWith('0x', $key->publicKey());
        self::assertStringStartsWith('0x', $key->privateKey());
        // Compressed by default: 33 bytes, so "0x" plus 66 hex characters.
        self::assertSame(68, strlen($key->publicKey()));
        self::assertSame(66, strlen($key->privateKey()));
        self::assertContains(substr($key->publicKey(), 2, 2), ['02', '03']);
    }

    public function testUncompressedGenerationIsAvailable(): void
    {
        $key = Secp256k1KeyPair::generate(compressed: false);

        self::assertSame(132, strlen($key->publicKey()));
        self::assertStringStartsWith('0x04', $key->publicKey());
        self::assertTrue($key->verify('x', $key->sign('x')));
    }

    /**
     * A key generated in either form must verify its own signatures, which
     * is what proves the point encoding is right rather than merely
     * plausible.
     */
    public function testAGeneratedKeyRoundTripsThroughItsOwnEncoding(): void
    {
        foreach ([true, false] as $compressed) {
            $key = Secp256k1KeyPair::generate($compressed);
            $restored = Secp256k1KeyPair::fromKeys($key->publicKey(), $key->privateKey());

            self::assertTrue($restored->verify('hello', $key->sign('hello')));
            self::assertTrue($key->verify('hello', $restored->sign('hello')));
        }
    }

    /**
     * A leading zero byte occurs roughly once in 400 keys, and a value that
     * dropped it is a different scalar to anything reading it strictly.
     */
    public function testPrivateKeysAreAlwaysLeftPaddedTo32Bytes(): void
    {
        for ($i = 0; $i < 500; $i++) {
            self::assertSame(66, strlen(Secp256k1KeyPair::generate()->privateKey()));
        }
    }

    /** The 0x prefix is part of what the ledger stores, not decoration. */
    public function testAKeyWithoutTheHexPrefixIsRefusedWithAnExplanation(): void
    {
        $valid = Secp256k1KeyPair::generate()->publicKey();

        try {
            Secp256k1KeyPair::fromPublicKey(substr($valid, 2));
            self::fail('a key without the 0x prefix was accepted');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('0x', $e->getMessage());
        }
    }

    public function testWrongLengthPublicKeyNamesBothValidLengths(): void
    {
        try {
            Secp256k1KeyPair::fromPublicKey('0x' . str_repeat('aa', 20));
            self::fail('a 20-byte public key was accepted');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('33', $e->getMessage());
            self::assertStringContainsString('65', $e->getMessage());
        }
    }

    /** A length and a point prefix that disagree means the forms got mixed. */
    public function testAPrefixThatContradictsTheLengthIsRejected(): void
    {
        try {
            Secp256k1KeyPair::fromPublicKey('0x04' . str_repeat('aa', 32));
            self::fail('a 33-byte key claiming to be uncompressed was accepted');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('0x04', $e->getMessage());
        }
    }

    public function testNonHexIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Secp256k1KeyPair::fromPublicKey('0xzzzz');
    }

    public function testVerifyOnlyKeyPairRefusesToSign(): void
    {
        $key = Secp256k1KeyPair::fromPublicKey($this->vectors()[0]['publicKey']);

        self::assertFalse($key->canSign());
        $this->expectException(\LogicException::class);
        $key->sign('anything');
    }

    public function testVerifyOnlyKeyPairHasNoPrivateKey(): void
    {
        $key = Secp256k1KeyPair::fromPublicKey($this->vectors()[0]['publicKey']);

        $this->expectException(\LogicException::class);
        $key->privateKey();
    }

    public function testMalformedSignatureReturnsFalse(): void
    {
        $v = $this->vectors()[0];
        $key = Secp256k1KeyPair::fromPublicKey($v['publicKey']);

        self::assertFalse($key->verify($v['message'], ''));
        self::assertFalse($key->verify($v['message'], str_repeat("\0", 10)));
        // A raw r||s pair rather than DER.
        self::assertFalse($key->verify($v['message'], str_repeat("\0", 64)));
    }

    /**
     * The ledger routes these to identical secp256k1 verification, so an
     * existing identity may carry either. They are never emitted.
     */
    public function testBitcoinAndEthereumParseAsSecp256k1(): void
    {
        foreach (['bitcoin', 'ethereum', 'secp256k1'] as $wire) {
            self::assertSame(KeyType::Secp256k1, KeyType::fromWire($wire));
            self::assertSame('secp256k1', KeyType::fromWire($wire)->value);
        }
    }

    public function testKeyTypeIsSecp256k1(): void
    {
        self::assertSame(KeyType::Secp256k1, Secp256k1KeyPair::generate()->keyType());
    }
}

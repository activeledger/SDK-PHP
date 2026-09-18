<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\KeyPair;
use Activeledger\KeyType;
use PHPUnit\Framework\TestCase;

/**
 * Conformance against the vectors published by the ledger repository.
 *
 * This is what makes "done" an observation rather than an assertion: the
 * signatures here were produced by the reference implementation and accepted
 * by a real network, so agreeing with them is agreeing with the thing that
 * matters.
 */
final class KeyPairTest extends TestCase
{
    public function testTheVectorFileHasMlDsaVectors(): void
    {
        self::assertGreaterThanOrEqual(6, count(Vectors::mlDsa()));
        self::assertGreaterThanOrEqual(12, count(Vectors::all()));
    }

    /**
     * The single most important interop fact: signatures the ledger accepted
     * verify here.
     */
    public function testVerifiesEveryPublishedSignature(): void
    {
        foreach (Vectors::mlDsa() as $vector) {
            $key = KeyPair::fromPublicKeyBase64($vector['publicKey']);

            self::assertTrue(
                $key->verify($vector['message'], base64_decode($vector['signature'])),
                "failed to verify published ml-dsa-65/{$vector['messageName']}"
            );
        }
    }

    public function testTamperedMessageDoesNotVerify(): void
    {
        foreach (Vectors::mlDsa() as $vector) {
            $key = KeyPair::fromPublicKeyBase64($vector['publicKey']);

            self::assertFalse(
                $key->verify($vector['message'] . ' ', base64_decode($vector['signature']))
            );
        }
    }

    /**
     * A caller checking a signature wants a yes or a no. A signature of the
     * wrong length is simply a no, not an exception.
     */
    public function testMalformedSignatureReturnsFalseRatherThanThrowing(): void
    {
        $vector = Vectors::mlDsa()[0];
        $key = KeyPair::fromPublicKeyBase64($vector['publicKey']);

        self::assertFalse($key->verify($vector['message'], ''));
        self::assertFalse($key->verify($vector['message'], str_repeat("\0", 10)));
        self::assertFalse($key->verify($vector['message'], str_repeat("\0", KeyPair::SIGNATURE_SIZE)));
    }

    /**
     * A Falcon signature is a different length entirely, so this checks the
     * length guard rather than the maths.
     */
    public function testAFalconSignatureDoesNotVerifyAsMlDsa(): void
    {
        $mldsa = Vectors::mlDsa()[0];
        $falcon = null;
        foreach (Vectors::all() as $vector) {
            if ($vector['type'] === 'falcon-512') {
                $falcon = $vector;
                break;
            }
        }

        self::assertNotNull($falcon);

        $key = KeyPair::fromPublicKeyBase64($mldsa['publicKey']);
        self::assertFalse($key->verify($mldsa['message'], base64_decode($falcon['signature'])));
    }

    public function testGeneratedKeysHaveTheDocumentedLengths(): void
    {
        $key = KeyPair::generate();

        self::assertSame(KeyPair::PUBLIC_KEY_SIZE, strlen(base64_decode($key->publicKeyBase64())));
        self::assertSame(KeyPair::SEED_SIZE, strlen(base64_decode($key->seedBase64())));
    }

    public function testSignatureLengthMatchesTheScheme(): void
    {
        $key = KeyPair::generate();

        self::assertSame(KeyPair::SIGNATURE_SIZE, strlen($key->sign('message')));
    }

    public function testFreshlyGeneratedKeysVerifyTheirOwnSignatures(): void
    {
        $key = KeyPair::generate();

        self::assertTrue($key->verify('round trip', $key->sign('round trip')));
    }

    /**
     * Deliberately NOT byte equality. The reference is hedged, so matching it
     * means being unable to reproduce it -- and a signer that DID reproduce it
     * would be deterministic, a different security posture adopted by accident.
     */
    public function testSigningIsHedgedSoTwoSignaturesDiffer(): void
    {
        $key = KeyPair::generate();

        $first = $key->sign('same message');
        $second = $key->sign('same message');

        self::assertNotSame($first, $second);
        self::assertTrue($key->verify('same message', $first));
        self::assertTrue($key->verify('same message', $second));
    }

    /**
     * An identity survives being stored and reloaded. Without this, a PHP
     * caller would have no usable identity at all.
     */
    public function testASeedRoundTripsToTheSameIdentity(): void
    {
        $original = KeyPair::generate();
        $restored = KeyPair::fromSeedBase64($original->seedBase64());

        self::assertSame($original->publicKeyBase64(), $restored->publicKeyBase64());
        self::assertTrue($original->verify('msg', $restored->sign('msg')));
        self::assertTrue($restored->verify('msg', $original->sign('msg')));
    }

    /**
     * THE most important guard in this SDK.
     *
     * The underlying library accepts any string as seed material: given a
     * 4032-byte private key from another SDK it hashes it, derives a
     * completely unrelated identity and signs happily. Every signature is then
     * rejected by the ledger as 1220 "Signature Incorrect" -- a message that
     * points nowhere near the cause.
     *
     * Verified behaviour of paragonie/pqcrypto_compat v0.3.2, not a guess.
     */
    public function testAForeignPrivateKeyIsRefusedByName(): void
    {
        $foreign = base64_decode(Vectors::mlDsa()[0]['privateKey']);
        self::assertSame(KeyPair::FOREIGN_PRIVATE_KEY_SIZE, strlen($foreign));

        try {
            KeyPair::fromSeed($foreign);
            self::fail('a 4032-byte private key was accepted');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('4032', $e->getMessage());
            self::assertStringContainsString('cannot use it', $e->getMessage());
        }
    }

    /**
     * Proves the danger the guard above exists for is real: without it, the
     * library silently derives a key that does not match the identity.
     */
    public function testTheUnderlyingLibraryWouldSilentlyDeriveTheWrongKey(): void
    {
        $vector = Vectors::mlDsa()[0];
        $foreign = base64_decode($vector['privateKey']);

        $wrong = (new \ParagonIE\PQCrypto\MLDSA65())->keyFromSeed($foreign);
        $derivedPublic = base64_encode($wrong['verificationKey']->bytes());

        // It produced a valid-looking key pair that is NOT the identity.
        self::assertNotSame($vector['publicKey'], $derivedPublic);
    }

    public function testWrongLengthSeedIsRejectedWithBothNumbers(): void
    {
        try {
            KeyPair::fromSeed(str_repeat("\0", 16));
            self::fail('a 16-byte seed was accepted');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('16', $e->getMessage());
            self::assertStringContainsString('32', $e->getMessage());
        }
    }

    public function testWrongLengthPublicKeyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        KeyPair::fromPublicKeyBase64(base64_encode(str_repeat("\0", 100)));
    }

    public function testNonBase64PublicKeyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        KeyPair::fromPublicKeyBase64('this is not base64!!');
    }

    public function testVerifyOnlyKeyPairRefusesToSign(): void
    {
        $key = KeyPair::fromPublicKeyBase64(Vectors::mlDsa()[0]['publicKey']);

        self::assertFalse($key->canSign());
        $this->expectException(\LogicException::class);
        $key->sign('anything');
    }

    public function testVerifyOnlyKeyPairHasNoSeed(): void
    {
        $key = KeyPair::fromPublicKeyBase64(Vectors::mlDsa()[0]['publicKey']);

        $this->expectException(\LogicException::class);
        $key->seedBase64();
    }

    public function testKeyTypeWireStringsAreExact(): void
    {
        self::assertSame('rsa', KeyType::Rsa->value);
        self::assertSame('secp256k1', KeyType::Secp256k1->value);
        self::assertSame('ml-dsa-65', KeyType::MlDsa65->value);
        self::assertSame('falcon-512', KeyType::Falcon512->value);

        self::assertSame(KeyType::MlDsa65, KeyType::fromWire('ml-dsa-65'));
        self::assertTrue(KeyType::MlDsa65->isPostQuantum());
        self::assertFalse(KeyType::Rsa->isPostQuantum());
    }

    public function testKeyTypeParsingIsCaseSensitive(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        KeyType::fromWire('ML-DSA-65');
    }

    public function testKeyPairReportsMlDsaAsItsType(): void
    {
        self::assertSame(KeyType::MlDsa65, KeyPair::generate()->keyType());
    }
}

<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\CanonicalJson;
use Activeledger\KeyPair;
use Activeledger\Transaction;
use PHPUnit\Framework\TestCase;

/**
 * The envelope shape, and the exact bytes covered by a signature.
 *
 * Everything here is checked by verifying with the public key rather than by
 * comparing signature bytes. Signing is hedged, so byte comparison would fail
 * against a correct implementation.
 */
final class TransactionTest extends TestCase
{
    private function decoded(Transaction $tx): array
    {
        return json_decode($tx->toJson(), true, 512, JSON_THROW_ON_ERROR);
    }

    public function testOnboardCarriesTypeSelfsignAndLabelKeyedSigs(): void
    {
        $key = KeyPair::generate();
        $doc = $this->decoded(Transaction::onboard($key));

        self::assertTrue($doc['$selfsign']);

        $identity = $doc['$tx']['$i']['identity'];
        self::assertSame('ml-dsa-65', $identity['type']);
        self::assertSame($key->publicKeyBase64(), $identity['publicKey']);

        // Keyed by the $i LABEL, not a stream id: there is no stream yet.
        self::assertArrayHasKey('identity', $doc['$sigs']);
    }

    public function testOnboardSignatureCoversTheTxObjectAndNothingElse(): void
    {
        $key = KeyPair::generate();
        $tx = Transaction::onboard($key);

        $signature = base64_decode($tx->sigs()['identity']);
        self::assertTrue($key->verify($tx->signedBytes(), $signature));

        // signedBytes is $tx alone. The envelope is strictly longer, and
        // signing IT is the single most common porting mistake.
        self::assertGreaterThan(strlen($tx->signedBytes()), strlen($tx->toJson()));
        self::assertFalse($key->verify($tx->toJson(), $signature));
    }

    /**
     * $o must be {} and not []. PHP is the only language here where that is
     * even possible to get wrong, and it changes the signed bytes.
     */
    public function testOnboardEmptyOutputsSerialiseAsAnObject(): void
    {
        $tx = Transaction::onboard(KeyPair::generate());

        self::assertStringContainsString('"$o":{}', $tx->signedBytes());
        self::assertStringNotContainsString('"$o":[]', $tx->signedBytes());
    }

    public function testOnboardLabelIsConfigurable(): void
    {
        $tx = Transaction::onboard(KeyPair::generate(), 'owner');

        self::assertArrayHasKey('owner', $tx->sigs());
        self::assertArrayHasKey('owner', $this->decoded($tx)['$tx']['$i']);
    }

    public function testBuiltTransactionHasNoSelfsignKeyAtAll(): void
    {
        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('transfer')
            ->input('streamid', KeyPair::generate())
            ->build();

        // Not "false" -- absent. $selfsign: false on a normal transaction
        // changes the signed bytes for no reason.
        self::assertArrayNotHasKey('$selfsign', $this->decoded($tx));
        self::assertFalse($tx->isSelfSigned());
    }

    public function testKeyOrderFollowsInsertionNotAlphabet(): void
    {
        $tx = Transaction::builder()
            ->namespace('zz')
            ->contract('aa')
            ->entry('mm')
            ->input('sid', KeyPair::generate())
            ->build();

        // $entry first, then $namespace, $contract, $i -- the order the JS SDK
        // writes, which is what the reference signs.
        self::assertStringStartsWith(
            '{"$entry":"mm","$namespace":"zz","$contract":"aa","$i":',
            $tx->signedBytes()
        );
    }

    public function testOptionalSectionsAreOmittedWhenEmpty(): void
    {
        $body = Transaction::builder()
            ->namespace('default')
            ->contract('noop')
            ->input('sid', KeyPair::generate())
            ->build()
            ->signedBytes();

        self::assertStringNotContainsString('$o', $body);
        self::assertStringNotContainsString('$r', $body);
        self::assertStringNotContainsString('$entry', $body);
    }

    public function testReadonlyStreamsLandInDollarR(): void
    {
        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('fetch')
            ->input('sid', KeyPair::generate())
            ->readonly('target', 'otherstream')
            ->build();

        self::assertSame('otherstream', $this->decoded($tx)['$tx']['$r']['target']);
    }

    public function testEverySignerSignsTheSameBytes(): void
    {
        $a = KeyPair::generate();
        $b = KeyPair::generate();

        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('multi')
            ->input('streamA', $a)
            ->input('streamB', $b)
            ->output('streamC')
            ->build();

        $message = $tx->signedBytes();

        self::assertCount(2, $tx->sigs());
        self::assertTrue($a->verify($message, base64_decode($tx->sigs()['streamA'])));
        self::assertTrue($b->verify($message, base64_decode($tx->sigs()['streamB'])));
    }

    public function testSigsAppearInTheOrderInputsWereAdded(): void
    {
        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('multi')
            ->input('zebra', KeyPair::generate())
            ->input('alpha', KeyPair::generate())
            ->build();

        self::assertSame(['zebra', 'alpha'], array_keys($tx->sigs()));

        $envelope = $tx->toJson();
        self::assertLessThan(strpos($envelope, 'alpha":"'), strpos($envelope, 'zebra":"'));
    }

    public function testReAddingAnInputReplacesItsKeyWithoutDuplicatingTheSignature(): void
    {
        $first = KeyPair::generate();
        $replacement = KeyPair::generate();

        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('c')
            ->input('sid', $first)
            ->input('sid', $replacement)
            ->build();

        self::assertCount(1, $tx->sigs());

        $signature = base64_decode($tx->sigs()['sid']);
        self::assertTrue($replacement->verify($tx->signedBytes(), $signature));
        self::assertFalse($first->verify($tx->signedBytes(), $signature));
    }

    public function testInputPayloadFieldsSurviveIntoTheSignedBody(): void
    {
        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('transfer')
            ->input('sid', KeyPair::generate(), ['amount' => 100])
            ->build();

        self::assertStringContainsString('"amount":100', $tx->signedBytes());
    }

    /**
     * An input with no payload is an object, and an empty one must still
     * serialise as {}.
     */
    public function testAnInputWithNoPayloadIsAnEmptyObject(): void
    {
        $tx = Transaction::builder()
            ->namespace('default')
            ->contract('c')
            ->input('sid', KeyPair::generate())
            ->build();

        self::assertStringContainsString('"sid":{}', $tx->signedBytes());
    }

    public function testBuildRefusesATransactionWithNoNamespace(): void
    {
        $this->expectException(\LogicException::class);
        Transaction::builder()->contract('c')->input('sid', KeyPair::generate())->build();
    }

    public function testBuildRefusesATransactionWithNoContract(): void
    {
        $this->expectException(\LogicException::class);
        Transaction::builder()->namespace('default')->input('sid', KeyPair::generate())->build();
    }

    /**
     * A transaction with no signer would serialise perfectly and be rejected
     * by the ledger with a message about signatures.
     */
    public function testBuildRefusesATransactionWithNoInput(): void
    {
        $this->expectException(\LogicException::class);
        Transaction::builder()->namespace('default')->contract('c')->build();
    }

    public function testEnvelopeIsRebuiltIdenticallyEachTime(): void
    {
        $tx = Transaction::onboard(KeyPair::generate());

        self::assertSame($tx->toJson(), $tx->toJson());
    }

    /**
     * A signature made here verifies with the public key the ledger will
     * store, which is the whole point of the exercise.
     */
    public function testAnOnboardEnvelopeIsInternallyConsistent(): void
    {
        $key = KeyPair::generate();
        $tx = Transaction::onboard($key);
        $doc = $this->decoded($tx);

        $stored = KeyPair::fromPublicKeyBase64($doc['$tx']['$i']['identity']['publicKey']);

        self::assertTrue($stored->verify(
            CanonicalJson::bytes($tx->body()),
            base64_decode($doc['$sigs']['identity'])
        ));
    }
}

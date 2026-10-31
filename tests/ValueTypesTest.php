<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\CanonicalJson;
use Activeledger\Identity;
use Activeledger\JsonObject;
use Activeledger\KeyPair;
use Activeledger\KeyType;
use Activeledger\LedgerEvent;
use PHPUnit\Framework\TestCase;

/** JsonObject's accessors, plus the small value types around keys. */
final class ValueTypesTest extends TestCase
{
    public function testAnEmptyObjectSerialisesAsBracesNotBrackets(): void
    {
        $empty = new JsonObject();

        self::assertTrue($empty->isEmpty());
        self::assertSame(0, $empty->count());
        self::assertSame('{}', CanonicalJson::encode($empty));
        self::assertSame('{}', CanonicalJson::encode(CanonicalJson::object([])));
    }

    public function testSetGetHasAndCount(): void
    {
        $o = (new JsonObject())->set('a', 1)->set('b', null);

        self::assertSame(2, $o->count());
        self::assertFalse($o->isEmpty());
        self::assertSame(1, $o->get('a'));
        self::assertTrue($o->has('b'), 'a null value is still present');
        self::assertNull($o->get('b'));
        self::assertFalse($o->has('c'));
        self::assertNull($o->get('c'));
    }

    public function testReplacingAKeyKeepsItsPosition(): void
    {
        $o = new JsonObject(['z' => 1, 'a' => 2]);
        $o->set('z', 9);

        self::assertSame(['z' => 9, 'a' => 2], $o->entries());
        self::assertSame('{"z":9,"a":2}', CanonicalJson::encode($o));
    }

    public function testNumericLookingKeysSurviveAsKeys(): void
    {
        $o = (new JsonObject())->set('0', 'x');

        self::assertSame('{"0":"x"}', CanonicalJson::encode($o));
    }

    public function testUnknownKeyTypeNamesTheOffendingString(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Unknown key type 'dsa'");
        KeyType::fromWire('dsa');
    }

    public function testEveryKeyTypeRoundTripsThroughItsWireString(): void
    {
        foreach (KeyType::cases() as $type) {
            self::assertSame($type, KeyType::fromWire($type->value));
        }
    }

    public function testOnlyThePostQuantumTypesReportAsSuch(): void
    {
        self::assertTrue(KeyType::Falcon512->isPostQuantum());
        self::assertFalse(KeyType::Secp256k1->isPostQuantum());
    }

    public function testAnIdentityExposesItsSignersPublicKey(): void
    {
        $key = KeyPair::generate();
        $identity = new Identity('stream-1', $key);

        self::assertSame('stream-1', $identity->streamId);
        self::assertSame($key, $identity->signer);
        self::assertSame($key->publicKey(), $identity->publicKey());
    }

    public function testAnEventPayloadThatIsAJsonScalarDecodesToIt(): void
    {
        self::assertSame('x', (new LedgerEvent(null, '"x"', '', null))->json());
        self::assertSame(7, (new LedgerEvent(null, '7', '', null))->json());
        self::assertNull((new LedgerEvent(null, '{broken', '', null))->json());
    }
}

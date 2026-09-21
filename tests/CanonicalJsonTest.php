<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\CanonicalJson;
use Activeledger\CanonicalJsonException;
use PHPUnit\Framework\TestCase;

/**
 * Checked against the bytes the JavaScript reference produced and a real
 * ledger accepted. If this file and my reading of JSON.stringify ever
 * disagree, this file is right.
 */
final class CanonicalJsonTest extends TestCase
{
    public function testAsciiBaseline(): void
    {
        self::assertSame(
            Vectors::reference('ascii'),
            CanonicalJson::encode(['greeting' => 'hello'])
        );
    }

    /**
     * Go's encoder escapes these and .NET's does too. Both look fine until a
     * payload contains an angle bracket.
     */
    public function testHtmlCharactersAreNotEscaped(): void
    {
        self::assertSame(
            Vectors::reference('html'),
            CanonicalJson::encode([
                'expr' => 'a < b && c > d',
                'amp' => 'Tom & Jerry',
            ])
        );
    }

    public function testNonAsciiIsRaw(): void
    {
        $got = CanonicalJson::encode(['greeting' => "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{2615}"]);

        self::assertSame(Vectors::reference('non-ascii'), $got);
        self::assertStringNotContainsString('\\u00e9', $got);
    }

    /**
     * PHP's json_encode escapes forward slashes as \/ by default. A base64
     * public key contains them constantly, so every onboard would sign the
     * wrong bytes.
     */
    public function testForwardSlashesAreNotEscaped(): void
    {
        $got = CanonicalJson::encode(['url' => 'http://example.com/a/b']);

        self::assertSame('{"url":"http://example.com/a/b"}', $got);
        self::assertStringNotContainsString('\\/', $got);
    }

    /**
     * The JavaScript number rule: one numeric type, so a whole float prints
     * without a fractional part.
     */
    public function testWholeFloatsPrintAsIntegers(): void
    {
        self::assertSame(
            Vectors::reference('float'),
            CanonicalJson::encode([
                'whole' => 1.0,
                'third' => 0.1,
                'negative' => -2.5,
                'zero' => 0,
            ])
        );
    }

    /**
     * The ledger does not canonicalise key order, so the signer reproduces
     * whatever order the caller built. These keys are not alphabetical.
     */
    public function testKeyOrderIsInsertionOrderNotSorted(): void
    {
        self::assertSame(
            Vectors::reference('ordering'),
            CanonicalJson::encode(['zebra' => 1, 'alpha' => 2, 'middle' => 3])
        );
    }

    /**
     * Documents why this class exists rather than merely asserting behaviour:
     * if PHP's defaults ever change, this test says so.
     */
    public function testJsonEncodeStillGetsItWrong(): void
    {
        $stdlib = json_encode(['url' => 'a/b', 'e' => "caf\u{e9}"]);

        self::assertStringContainsString('\\/', (string) $stdlib);
        self::assertStringContainsString('\\u00e9', (string) $stdlib);
    }

    public function testOnboardShapeMatchesReference(): void
    {
        $reference = Vectors::reference('onboard');
        $parsed = json_decode($reference, true);
        $identity = $parsed['$i']['identity'];

        $built = [
            '$namespace' => 'default',
            '$contract' => 'onboard',
            '$i' => [
                'identity' => [
                    'type' => $identity['type'],
                    'publicKey' => $identity['publicKey'],
                ],
            ],
            '$o' => CanonicalJson::object(),
        ];

        self::assertSame($reference, CanonicalJson::encode($built));
    }

    /**
     * The ambiguity that only PHP has: [] is both an empty array and an empty
     * object, and $o is an object. Getting it wrong changes the signed bytes.
     */
    public function testEmptyObjectSerialisesAsObjectNotArray(): void
    {
        self::assertSame('{}', CanonicalJson::encode(CanonicalJson::object()));
        self::assertSame('[]', CanonicalJson::encode([]));
        self::assertSame('{"$o":{}}', CanonicalJson::encode(['$o' => CanonicalJson::object()]));
        self::assertSame('{"$o":[]}', CanonicalJson::encode(['$o' => []]));
    }

    public function testNestedStructuresArraysAndNull(): void
    {
        self::assertSame(
            '{"a":[1,"two",true,null],"b":{"c":false}}',
            CanonicalJson::encode([
                'a' => [1, 'two', true, null],
                'b' => ['c' => false],
            ])
        );
    }

    public function testEscapesOnlyWhatJsonRequires(): void
    {
        self::assertSame(
            '{"s":"a\\"b\\\\c"}',
            CanonicalJson::encode(['s' => 'a"b\\c'])
        );
    }

    public function testControlCharacters(): void
    {
        // Built rather than written as a literal: an escape sequence in source
        // can be helpfully converted into the character itself, and the test
        // would then assert the opposite of what it means.
        $expected = '{"s":"\\n\\t\\u' . sprintf('%04x', 1) . '"}';

        self::assertSame(
            $expected,
            CanonicalJson::encode(['s' => "\n\t" . chr(1)])
        );
    }

    /**
     * JSON.stringify emits null for these, which would sign bytes the caller
     * never intended.
     */
    public function testNanIsRefused(): void
    {
        $this->expectException(CanonicalJsonException::class);
        CanonicalJson::encode(['x' => NAN]);
    }

    public function testInfinityIsRefused(): void
    {
        $this->expectException(CanonicalJsonException::class);
        CanonicalJson::encode(['x' => INF]);
    }

    /**
     * A key that looks numeric becomes an int key in PHP. JSON keys are always
     * strings, so it has to go back.
     */
    public function testNumericStringKeysStaySerialisedAsStrings(): void
    {
        self::assertSame('{"1":"a","02":"b"}', CanonicalJson::encode(['1' => 'a', '02' => 'b']));
    }

    public function testJsonObjectPreservesInsertionOrderIncludingReplacement(): void
    {
        $object = CanonicalJson::object()->set('a', 1)->set('b', 2)->set('a', 3);

        self::assertSame('{"a":3,"b":2}', CanonicalJson::encode($object));
    }

    public function testBytesAreTheSameAsTheEncodedString(): void
    {
        $value = ['e' => "\u{e9}"];

        self::assertSame(CanonicalJson::encode($value), CanonicalJson::bytes($value));
        self::assertSame(10, strlen(CanonicalJson::bytes($value)));
    }

    /**
     * Large integers take DOUBLE precision, which reverses what this test
     * used to assert.
     *
     * Keeping PHP's exact integer looked like the careful choice, but the
     * ledger verifies a re-stringified $tx: `keypair.ts` does
     * `JSON.stringify(data)` on the object its HTTP layer already parsed. So
     * 9007199254740993 on the wire becomes the double 9007199254740992 before
     * anything is verified, and a signature over the exact integer cannot
     * match. Preserving the precision produced a document the ledger rejects
     * as 1220 "Signature Incorrect".
     *
     * JavaScript has no integer type; this is the same value a browser would
     * have sent.
     */
    public function testLargeIntegersTakeDoublePrecisionLikeJavaScript(): void
    {
        self::assertSame(
            '{"big":9007199254740992}',
            CanonicalJson::encode(['big' => 9007199254740993])
        );

        // Below 2**53 nothing is lost.
        self::assertSame(
            '{"big":9007199254740991}',
            CanonicalJson::encode(['big' => 9007199254740991])
        );
    }

    public function testUnsupportedTypeIsRefusedRatherThanGuessed(): void
    {
        $this->expectException(CanonicalJsonException::class);
        CanonicalJson::encode(['x' => new \stdClass()]);
    }
}

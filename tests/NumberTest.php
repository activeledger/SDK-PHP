<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\CanonicalJson;
use PHPUnit\Framework\TestCase;

/**
 * Canonical number formatting, against the published vectors.
 *
 * What gets signed is JSON.stringify($tx) and the ledger verifies by
 * re-stringifying the $tx it parsed, so JavaScript's number formatting is the
 * specification. A number written differently produces a signature the ledger
 * rejects as 1220, with nothing in the message about numbers.
 *
 * These exist because the `float` case in pq-vectors.json - 1, 0.1, -2.5, 0 -
 * sits entirely inside the range where every language already agrees.
 */
final class NumberTest extends TestCase
{
    /** @return list<array<string, mixed>> */
    private static function vectors(): array
    {
        $raw = file_get_contents(__DIR__ . '/data/number-vectors.json');
        self::assertNotFalse($raw, 'number-vectors.json is missing');

        return json_decode($raw, true)['vectors'];
    }

    public function testEveryPublishedNumberFormatsIdentically(): void
    {
        foreach (self::vectors() as $v) {
            self::assertSame(
                $v['expected'],
                CanonicalJson::jsNumber((float) $v['value']),
                "jsNumber({$v['name']})"
            );
        }
    }

    /** The formatter being right is not enough if the encoder does not call it. */
    public function testTheEncoderUsesIt(): void
    {
        foreach (self::vectors() as $v) {
            self::assertSame(
                '{"n":' . $v['expected'] . '}',
                CanonicalJson::encode(['n' => (float) $v['value']]),
                "encode({$v['name']})"
            );
        }
    }

    /**
     * A whole float above PHP_INT_MAX used to be cast to int and wrap.
     *
     * 1e19 came out as -8446744073709551616 - a negative number from a
     * positive input, with a PHP warning nobody reads in a signing path.
     */
    public function testLargeWholeFloatsNoLongerOverflowToNegative(): void
    {
        foreach ([1e19, 1e20, 5e18] as $value) {
            $encoded = CanonicalJson::encode(['n' => $value]);

            self::assertStringNotContainsString('-', $encoded, "1e19-class value went negative: $encoded");
        }

        self::assertSame('{"n":10000000000000000000}', CanonicalJson::encode(['n' => 1e19]));
    }

    public function testNegativeZeroLosesItsSign(): void
    {
        self::assertSame('{"n":0}', CanonicalJson::encode(['n' => -0.0]));
    }

    public function testIntegersBeyondTwoToThe53TakeDoublePrecision(): void
    {
        // JavaScript has no integer type, so the ledger parses this into a
        // double whatever is sent. Signing the unrounded value gives a
        // signature it cannot verify.
        self::assertSame('{"n":9007199254740992}', CanonicalJson::encode(['n' => 9007199254740993]));
    }

    public function testExponentHasNoLeadingZeros(): void
    {
        self::assertSame('{"n":1e-7}', CanonicalJson::encode(['n' => 1e-7]));
        self::assertSame('{"n":1e+21}', CanonicalJson::encode(['n' => 1e21]));
    }

    /** Both sides of both boundaries - where implementations part company. */
    public function testThePlainExponentBoundaries(): void
    {
        self::assertSame('{"n":100000000000000000000}', CanonicalJson::encode(['n' => 1e20]));
        self::assertSame('{"n":1e+21}', CanonicalJson::encode(['n' => 1e21]));
        self::assertSame('{"n":0.000001}', CanonicalJson::encode(['n' => 1e-6]));
        self::assertSame('{"n":1e-7}', CanonicalJson::encode(['n' => 1e-7]));
    }
}

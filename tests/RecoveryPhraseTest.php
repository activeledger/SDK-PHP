<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\KeyType;
use Activeledger\RecoveryPhrase;
use PHPUnit\Framework\TestCase;

/**
 * RecoveryPhrase::validate and deriveSeed: each way a phrase or seed can be
 * refused, and the shapes of input that must be accepted. The derivations
 * themselves are checked against the published vectors in SeedTest.
 */
final class RecoveryPhraseTest extends TestCase
{
    private const TWELVE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    /**
     * Zero-entropy phrases of every valid length. Their last word is the only
     * one that changes, because it carries the checksum.
     *
     * @return array<string, array{string, int}>
     */
    public static function validPhrases(): array
    {
        $phrases = [];
        foreach ([12 => 'about', 15 => 'address', 18 => 'agent', 21 => 'admit', 24 => 'art'] as $count => $last) {
            $phrases["$count words"] = [
                implode(' ', array_merge(array_fill(0, $count - 1, 'abandon'), [$last])),
                $count,
            ];
        }

        return $phrases;
    }

    /**
     * @dataProvider validPhrases
     */
    public function testEveryValidLengthPassesItsChecksum(string $phrase, int $count): void
    {
        self::assertCount($count, explode(' ', RecoveryPhrase::validate($phrase)));
    }

    /**
     * @dataProvider validPhrases
     */
    public function testChangingTheChecksumWordFailsEveryLength(string $phrase, int $count): void
    {
        $words = explode(' ', $phrase);
        // 'zoo' is the last word of the list, and none of the valid last
        // words above, so this always changes the checksum bits.
        $words[$count - 1] = 'zoo';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/checksum/');
        RecoveryPhrase::validate(implode(' ', $words));
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function wrongWordCounts(): array
    {
        $words = static fn(int $n): string => implode(' ', array_fill(0, $n, 'abandon'));

        return [
            'empty' => ['', 0],
            'only whitespace' => ["  \t\n ", 0],
            'one short of the minimum' => [$words(11), 11],
            'inside the range, not a multiple of three' => [$words(13), 13],
            'also inside the range' => [$words(14), 14],
            'just under the maximum' => [$words(23), 23],
            'one over the maximum' => [$words(25), 25],
            'a multiple of three beyond the maximum' => [$words(27), 27],
        ];
    }

    /**
     * @dataProvider wrongWordCounts
     */
    public function testAnInvalidWordCountIsReportedWithTheCountGiven(string $phrase, int $count): void
    {
        try {
            RecoveryPhrase::validate($phrase);
            self::fail("accepted a phrase of $count words");
        } catch (\InvalidArgumentException $e) {
            self::assertSame("a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got $count", $e->getMessage());
        }
    }

    public function testTheWordCountIsCheckedBeforeTheWordlist(): void
    {
        // Eleven words that are not words: the count error wins, so a caller
        // who pasted half a phrase is told it is short, not that it is wrong.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/got 11$/');
        RecoveryPhrase::validate(implode(' ', array_fill(0, 11, 'zzzz')));
    }

    public function testTheOffendingWordIsReportedByPosition(): void
    {
        $words = explode(' ', self::TWELVE);
        $words[4] = 'notaword';

        try {
            RecoveryPhrase::validate(implode(' ', $words));
            self::fail('accepted a word outside the wordlist');
        } catch (\InvalidArgumentException $e) {
            self::assertSame(
                'word 5 ("notaword") is not in the BIP-39 English wordlist',
                $e->getMessage()
            );
        }
    }

    public function testTheFirstOfSeveralBadWordsIsTheOneReported(): void
    {
        $words = explode(' ', self::TWELVE);
        $words[2] = 'qqqq';
        $words[9] = 'wwww';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('word 3 ("qqqq")');
        RecoveryPhrase::validate(implode(' ', $words));
    }

    public function testWordsAreCaseSensitive(): void
    {
        // The wordlist is lower case; accepting 'Abandon' would mean the same
        // phrase in two spellings, one of which other SDKs refuse.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('word 1 ("Abandon")');
        RecoveryPhrase::validate('Abandon' . substr(self::TWELVE, strlen('abandon')));
    }

    public function testAWordIsMatchedWholeNotByPrefix(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('word 12 ("abou")');
        RecoveryPhrase::validate(substr(self::TWELVE, 0, -1));
    }

    public function testAnyRunOfWhitespaceSeparatesWordsAndIsNormalisedAway(): void
    {
        $messy = "\n abandon\tabandon  abandon abandon abandon abandon\r\nabandon abandon abandon abandon abandon   about \t";

        self::assertSame(self::TWELVE, RecoveryPhrase::validate($messy));
    }

    public function testMessyAndTidyPhrasesGiveTheSameSeed(): void
    {
        self::assertSame(
            RecoveryPhrase::toSeed(self::TWELVE),
            RecoveryPhrase::toSeed(str_replace(' ', "  \t", self::TWELVE))
        );
    }

    public function testASeedIsRefusedBeforeAnythingIsDerivedFromIt(): void
    {
        foreach ([0, 32, 63, 65] as $length) {
            try {
                RecoveryPhrase::deriveSeed(KeyType::MlDsa65, str_repeat("\x01", $length));
                self::fail("derived from a $length-byte BIP-39 seed");
            } catch (\InvalidArgumentException $e) {
                self::assertSame("a BIP-39 seed is 64 bytes, got $length", $e->getMessage());
            }
        }
    }

    public function testRsaCannotBeDerivedFromASeed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('rsa keys cannot be derived');
        RecoveryPhrase::deriveSeed(KeyType::Rsa, str_repeat("\x01", 64));
    }

    public function testDerivedSeedLengthsMatchTheirAlgorithms(): void
    {
        $bip39 = RecoveryPhrase::toSeed(self::TWELVE);

        self::assertSame(32, strlen(RecoveryPhrase::deriveSeed(KeyType::MlDsa65, $bip39)));
        self::assertSame(48, strlen(RecoveryPhrase::deriveSeed(KeyType::Falcon512, $bip39)));
        self::assertSame(32, strlen(RecoveryPhrase::deriveSeed(KeyType::Secp256k1, $bip39)));
    }

    public function testThePassphraseIsPartOfTheSeedButNotOfValidation(): void
    {
        // A passphrase never makes a phrase invalid -- that is what lets a
        // wrong one derive a different, valid, unowned identity -- so it is
        // the one input that cannot be checked.
        self::assertNotSame(
            RecoveryPhrase::toSeed(self::TWELVE),
            RecoveryPhrase::toSeed(self::TWELVE, 'x')
        );
        self::assertSame(64, strlen(RecoveryPhrase::toSeed(self::TWELVE, 'x')));
    }
}

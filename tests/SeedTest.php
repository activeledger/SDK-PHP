<?php

declare(strict_types=1);

namespace Activeledger\Tests;

use Activeledger\KeyPair;
use Activeledger\KeyType;
use Activeledger\RecoveryPhrase;
use Activeledger\Secp256k1KeyPair;
use PHPUnit\Framework\TestCase;

/**
 * Seed and recovery-phrase derivation, against the published cross-language
 * vectors.
 *
 * The vectors matter more here than elsewhere. Six other SDKs derive keys
 * from the same seeds and phrases, and a derivation that drifts does not
 * fail loudly - it produces a perfectly valid key for an identity that is
 * not the caller's, and the only symptom arrives much later as 1220
 * "Signature Incorrect" from somewhere else entirely.
 *
 * This is also the SDK that gains most from seeds. Its ml-dsa-65 private key
 * IS a 32-byte seed, so before fromSeed existed elsewhere an identity made
 * here could not be used anywhere else, and no other SDK's identity could be
 * used here.
 */
final class SeedTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function doc(): array
    {
        static $doc = null;
        if ($doc === null) {
            $raw = file_get_contents(__DIR__ . '/data/seed-vectors.json');
            self::assertNotFalse($raw, 'seed-vectors.json is missing');
            $doc = json_decode($raw, true);
        }

        return $doc;
    }

    /** @return list<array<string, mixed>> */
    private static function seedVectors(?string $type = null, ?bool $valid = true): array
    {
        return array_values(array_filter(
            self::doc()['seedVectors'],
            static fn(array $v): bool =>
                ($type === null || $v['type'] === $type)
                && ($valid === null || ($v['valid'] ?? true) === $valid)
        ));
    }

    /** @return list<array<string, mixed>> */
    private static function phraseVectors(string $type, string $scheme = 'v1'): array
    {
        return array_values(array_filter(
            self::doc()['phraseVectors'],
            static fn(array $v): bool => $v['type'] === $type && $v['scheme'] === $scheme
        ));
    }

    public function testTheVectorFileCoversEveryTypeThisSdkSupports(): void
    {
        // A file that lost a type would otherwise pass every test below by
        // simply not exercising it.
        self::assertNotEmpty(self::seedVectors('ml-dsa-65'));
        self::assertNotEmpty(self::seedVectors('secp256k1'));
        self::assertNotEmpty(self::phraseVectors('ml-dsa-65'));
        self::assertNotEmpty(self::phraseVectors('secp256k1'));
        self::assertGreaterThanOrEqual(2, count(self::seedVectors(null, false)));
    }

    // -- ml-dsa-65 --------------------------------------------------------

    public function testMlDsaFromSeedReproducesEveryPublishedKey(): void
    {
        foreach (self::seedVectors('ml-dsa-65') as $v) {
            $key = KeyPair::fromSeed(hex2bin($v['seed']));

            self::assertSame($v['publicKey'], $key->publicKey(), "ml-dsa-65/{$v['seedName']}");
        }
    }

    public function testMlDsaFromPhraseReproducesEveryPublishedKey(): void
    {
        foreach (self::phraseVectors('ml-dsa-65') as $v) {
            $key = KeyPair::fromPhrase($v['phrase'], $v['passphrase']);

            self::assertSame($v['publicKey'], $key->publicKey(), "phrase {$v['phraseName']}");
        }
    }

    public function testMlDsaSeedDerivationMatchesThePublishedIntermediate(): void
    {
        // Checked separately from the key so a failure says WHICH step drifted.
        foreach (self::phraseVectors('ml-dsa-65') as $v) {
            $bip39 = RecoveryPhrase::toSeed($v['phrase'], $v['passphrase']);
            self::assertSame($v['bip39Seed'], bin2hex($bip39), "bip39 seed {$v['phraseName']}");

            self::assertSame(
                $v['derivedSeed'],
                bin2hex(RecoveryPhrase::deriveSeed(KeyType::MlDsa65, $bip39)),
                "derived seed {$v['phraseName']}"
            );
        }
    }

    // -- secp256k1 --------------------------------------------------------

    public function testSecp256k1FromSeedReproducesEveryPublishedKey(): void
    {
        foreach (self::seedVectors('secp256k1') as $v) {
            $key = Secp256k1KeyPair::fromSeed(hex2bin($v['seed']), $v['publicKeyForm'] === 'compressed');

            self::assertSame($v['publicKey'], $key->publicKey(), "{$v['seedName']}/{$v['publicKeyForm']}");
            self::assertSame($v['privateKey'], $key->privateKey(), "{$v['seedName']}/{$v['publicKeyForm']}");
        }
    }

    public function testSecp256k1FromPhraseReproducesEveryPublishedKey(): void
    {
        foreach (self::phraseVectors('secp256k1') as $v) {
            $key = Secp256k1KeyPair::fromPhrase(
                $v['phrase'],
                $v['passphrase'],
                $v['publicKeyForm'] === 'compressed'
            );

            self::assertSame($v['publicKey'], $key->publicKey(), "phrase {$v['phraseName']}");
            self::assertSame($v['privateKey'], $key->privateKey(), "phrase {$v['phraseName']}");
        }
    }

    public function testTheLegacyPhraseSchemeReproducesEveryPublishedKey(): void
    {
        foreach (self::phraseVectors('secp256k1', 'legacy') as $v) {
            $key = Secp256k1KeyPair::fromLegacyPhrase($v['phrase'], $v['publicKeyForm'] === 'compressed');

            self::assertSame($v['publicKey'], $key->publicKey(), "legacy {$v['phraseName']}");
        }
    }

    /**
     * A scalar outside [1, n-1] must be refused, never reduced.
     *
     * Reducing mod n returns a perfectly functional key for a different
     * identity, and nothing downstream ever reports a problem - which is why
     * these seeds are published rather than only described.
     */
    public function testAnInvalidScalarIsRefusedRatherThanReduced(): void
    {
        foreach (self::seedVectors('secp256k1', false) as $v) {
            try {
                Secp256k1KeyPair::fromSeed(hex2bin($v['seed']));
                self::fail("accepted an invalid scalar ({$v['seedName']})");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('[1, n-1]', $e->getMessage());
            }
        }
    }

    // -- shape ------------------------------------------------------------

    public function testASeedOfTheWrongLengthIsRefusedRatherThanPadded(): void
    {
        // Padding would produce a valid key for a different identity - the
        // same failure as reducing a scalar, by another route.
        foreach ([31, 33, 48, 0] as $length) {
            try {
                Secp256k1KeyPair::fromSeed(str_repeat("\x01", $length));
                self::fail("accepted a $length-byte secp256k1 seed");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('32-byte seed', $e->getMessage());
            }
        }
    }

    public function testEachKeyTypeDerivesADifferentSeedFromOnePhrase(): void
    {
        // Domain separation. Without it one phrase gives an ml-dsa-65 seed
        // equal to the secp256k1 scalar, so two identities share entropy.
        $bip39 = RecoveryPhrase::toSeed(self::phraseVectors('ml-dsa-65')[0]['phrase']);

        $seeds = [
            bin2hex(RecoveryPhrase::deriveSeed(KeyType::MlDsa65, $bip39)),
            bin2hex(RecoveryPhrase::deriveSeed(KeyType::Falcon512, $bip39)),
            bin2hex(RecoveryPhrase::deriveSeed(KeyType::Secp256k1, $bip39)),
        ];

        self::assertCount(3, array_unique($seeds));
    }

    public function testAPassphraseChangesTheIdentity(): void
    {
        $phrase = self::phraseVectors('ml-dsa-65')[0]['phrase'];

        self::assertNotSame(
            KeyPair::fromPhrase($phrase)->publicKey(),
            KeyPair::fromPhrase($phrase, 'TREZOR')->publicKey()
        );
    }

    public function testASeedDerivedKeySignsAndVerifies(): void
    {
        $seed = str_repeat("\x11", 32);

        $mldsa = KeyPair::fromSeed($seed);
        self::assertTrue($mldsa->verify('payload', $mldsa->sign('payload')));

        $ec = Secp256k1KeyPair::fromSeed($seed);
        self::assertTrue($ec->verify('payload', $ec->sign('payload')));
    }

    public function testTheSameSeedAlwaysDerivesTheSameKey(): void
    {
        $seed = str_repeat("\x5a", 32);

        self::assertSame(KeyPair::fromSeed($seed)->publicKey(), KeyPair::fromSeed($seed)->publicKey());
        self::assertSame(
            Secp256k1KeyPair::fromSeed($seed)->publicKey(),
            Secp256k1KeyPair::fromSeed($seed)->publicKey()
        );
    }

    // -- phrase validation ------------------------------------------------

    /**
     * An unchecked phrase is a silent failure, not a loud one: it derives a
     * perfectly valid key for an identity nobody owns.
     */
    public function testAPhraseWithABadChecksumIsRejected(): void
    {
        // Real words, valid length, wrong checksum.
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/checksum/');
        RecoveryPhrase::toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon');
    }

    public function testAWordOutsideTheWordlistIsNamed(): void
    {
        try {
            RecoveryPhrase::toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzz');
            self::fail('accepted a word that is not in the wordlist');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('zzzz', $e->getMessage());
            self::assertStringContainsString('12', $e->getMessage());
        }
    }

    public function testAWrongWordCountIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/12, 15, 18, 21 or 24/');
        RecoveryPhrase::toSeed('abandon abandon abandon');
    }

    public function testExtraWhitespaceIsToleratedNotRejected(): void
    {
        $phrase = self::phraseVectors('ml-dsa-65')[0]['phrase'];

        self::assertSame(
            KeyPair::fromPhrase($phrase)->publicKey(),
            KeyPair::fromPhrase("  $phrase  ")->publicKey()
        );
    }

    public function testEverySupportedWordCountIsAccepted(): void
    {
        // 12 and 24 are the common ones; the others exist and a length check
        // that only knows about two of them rejects valid phrases.
        foreach (self::doc()['phraseVectors'] as $v) {
            $words = count(preg_split('/\s+/', trim($v['phrase'])));
            self::assertContains($words, [12, 15, 18, 21, 24]);
        }

        self::assertSame(2048, count(file(__DIR__ . '/../resources/bip39-english.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));
    }
}

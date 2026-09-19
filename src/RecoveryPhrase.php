<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * BIP-39 recovery phrases, and the seed each key type derives from one.
 *
 * ## The two layers
 *
 * A phrase becomes a 64-byte BIP-39 seed, and that seed becomes the seed the
 * chosen algorithm actually takes. They are different lengths and different
 * constructions, and `deriveSeed` is the step between them.
 *
 * ## The derivation
 *
 *   BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, "mnemonic" + passphrase,
 *                                      2048 iterations, 64 bytes)
 *
 *   ml-dsa-65   HKDF-SHA512(S, salt = "", info = "activeledger-seed-v1:ml-dsa-65", 32)
 *   falcon-512  HKDF-SHA512(S, salt = "", info = "activeledger-seed-v1:falcon-512", 48)
 *   secp256k1   HMAC-SHA512("Bitcoin seed", S)[0..32]
 *
 * secp256k1 does not use HKDF, and that is not an oversight. The JavaScript
 * SDK has shipped `restoreBIP39Key` with the construction above since before
 * the post-quantum types existed, so phrases are already in use. Changing it
 * would hand every one of those users a different key for a phrase that used
 * to work - not an error, just an identity that is no longer theirs. The
 * post-quantum types are new and carry no such debt, so they get the
 * construction with proper domain separation.
 *
 * Published, with cross-language vectors, in the JavaScript SDK's
 * `vectors/seed-vectors.json`.
 */
final class RecoveryPhrase
{
    /** BIP-39's fixed PBKDF2 parameters. Not tunable; changing one changes every identity. */
    private const ITERATIONS = 2048;
    private const SEED_SIZE = 64;

    /** @var list<string>|null */
    private static ?array $wordlist = null;

    /**
     * Turns a recovery phrase into its 64-byte BIP-39 seed.
     *
     * The phrase IS validated - word membership and the checksum both. A
     * mistyped phrase that is not checked does not fail: it derives a
     * perfectly valid key for an identity nobody owns, and the only symptom
     * is that the ledger does not recognise it.
     *
     * @throws \InvalidArgumentException if the phrase is not a valid mnemonic
     */
    public static function toSeed(string $phrase, string $passphrase = ''): string
    {
        $normalised = self::validate($phrase);

        return hash_pbkdf2(
            'sha512',
            $normalised,
            // BIP-39's salt. The passphrase is appended to the literal
            // "mnemonic", not used as a separate argument.
            'mnemonic' . self::normaliseUtf8($passphrase),
            self::ITERATIONS,
            self::SEED_SIZE,
            true
        );
    }

    /**
     * Turns a BIP-39 seed into the seed the given key type takes.
     *
     * @throws \InvalidArgumentException if the type has no seed derivation
     */
    public static function deriveSeed(KeyType $type, string $bip39Seed): string
    {
        if (strlen($bip39Seed) !== self::SEED_SIZE) {
            throw new \InvalidArgumentException(sprintf(
                'a BIP-39 seed is %d bytes, got %d',
                self::SEED_SIZE,
                strlen($bip39Seed)
            ));
        }

        return match ($type) {
            // An empty salt means a block of zero bytes of the hash length,
            // which is what RFC 5869 specifies and what hash_hkdf does -
            // checked byte for byte against node's crypto.hkdfSync.
            KeyType::MlDsa65 => hash_hkdf('sha512', $bip39Seed, 32, 'activeledger-seed-v1:ml-dsa-65', ''),
            KeyType::Falcon512 => hash_hkdf('sha512', $bip39Seed, 48, 'activeledger-seed-v1:falcon-512', ''),
            KeyType::Secp256k1 => substr(hash_hmac('sha512', $bip39Seed, 'Bitcoin seed', true), 0, 32),
            KeyType::Rsa => throw new \InvalidArgumentException(
                'rsa keys cannot be derived from a seed, and this SDK does not support rsa at all'
            ),
        };
    }

    /**
     * Checks a phrase and returns it normalised.
     *
     * @throws \InvalidArgumentException
     * @return string the phrase, single-spaced and NFKD-normalised
     */
    public static function validate(string $phrase): string
    {
        $normalised = self::normaliseUtf8($phrase);
        $words = preg_split('/\s+/u', trim($normalised), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $count = count($words);

        // 12, 15, 18, 21 and 24 words are the only valid lengths.
        if ($count < 12 || $count > 24 || $count % 3 !== 0) {
            throw new \InvalidArgumentException(sprintf(
                'a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got %d',
                $count
            ));
        }

        $list = self::wordlist();
        $bits = '';
        foreach ($words as $position => $word) {
            $index = array_search($word, $list, true);
            if ($index === false) {
                throw new \InvalidArgumentException(sprintf(
                    'word %d ("%s") is not in the BIP-39 English wordlist',
                    $position + 1,
                    $word
                ));
            }
            $bits .= str_pad(decbin($index), 11, '0', STR_PAD_LEFT);
        }

        // The last few bits are a checksum over the entropy, which is what
        // catches a typo that happens to land on another real word.
        $checksumBits = intdiv($count, 3);
        $entropyBits = strlen($bits) - $checksumBits;

        $entropy = '';
        foreach (str_split(substr($bits, 0, $entropyBits), 8) as $byte) {
            $entropy .= chr((int) bindec($byte));
        }

        $expected = substr(
            str_pad(decbin(ord(hash('sha256', $entropy, true)[0])), 8, '0', STR_PAD_LEFT),
            0,
            $checksumBits
        );

        if (substr($bits, $entropyBits) !== $expected) {
            throw new \InvalidArgumentException(
                'the BIP-39 checksum does not match - the phrase has a typo or the words are '
                . 'in the wrong order. Deriving from it anyway would produce a valid key for '
                . 'an identity nobody owns.'
            );
        }

        return implode(' ', $words);
    }

    /**
     * NFKD, as BIP-39 requires.
     *
     * Only matters for non-English wordlists and for passphrases, which may
     * contain anything - but a passphrase that normalises differently derives
     * a different seed, so it is applied on both.
     */
    private static function normaliseUtf8(string $value): string
    {
        if (class_exists(\Normalizer::class)) {
            $normalised = \Normalizer::normalize($value, \Normalizer::FORM_KD);
            if ($normalised !== false) {
                return $normalised;
            }
        }

        // intl is not always built in. ASCII phrases and passphrases are
        // unaffected either way; a non-ASCII passphrase without intl is the
        // one case that could differ, and it fails loudly on use rather than
        // silently here.
        return $value;
    }

    /** @return list<string> */
    private static function wordlist(): array
    {
        if (self::$wordlist === null) {
            $path = __DIR__ . '/../resources/bip39-english.txt';
            $contents = @file_get_contents($path);

            if ($contents === false) {
                throw new \RuntimeException("The BIP-39 wordlist is missing from $path");
            }

            $words = preg_split('/\r?\n/', trim($contents), -1, PREG_SPLIT_NO_EMPTY) ?: [];
            if (count($words) !== 2048) {
                throw new \RuntimeException(sprintf(
                    'The BIP-39 wordlist should hold 2048 words, found %d',
                    count($words)
                ));
            }

            self::$wordlist = $words;
        }

        return self::$wordlist;
    }
}

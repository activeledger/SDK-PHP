<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * A secp256k1 identity, encoded the way Activeledger stores it.
 *
 * ## Why OpenSSL rather than a curve library
 *
 * PHP's `ext-openssl` supports secp256k1 natively, and it is the **same
 * implementation the ledger itself verifies with**, so interop is structural
 * rather than hopeful. It also needs no new Composer package and no `ext-gmp`
 * — `simplito/elliptic-php` requires GMP outright, which is a real deployment
 * burden for a client SDK.
 *
 * ## The one thing this SDK cannot do that the others can
 *
 * OpenSSL signs with a **random k**, and offers no way to inject one. So
 * unlike the JavaScript, JVM, C#, Go and Rust SDKs, this one is **not RFC 6979
 * deterministic** and cannot reproduce the published `deterministicSignature`
 * bytes. Signing the same message twice gives different bytes.
 *
 * That costs a test, not correctness. Every signature this SDK emits is a
 * valid, canonical, low-S signature the ledger and every other SDK accept —
 * it simply cannot be compared byte for byte. Implementing RFC 6979 here would
 * mean hand-rolling 256-bit modular arithmetic and point multiplication in
 * pure PHP, which is a far worse trade than losing an exact-comparison test.
 */
final class Secp256k1KeyPair implements Signer
{
    /** SEC1 public key lengths. The ledger accepts both. */
    public const PUBLIC_KEY_COMPRESSED_SIZE = 33;
    public const PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;

    /** The private scalar, always this many bytes. */
    public const PRIVATE_KEY_SIZE = 32;

    /**
     * DER prefixes for a SubjectPublicKeyInfo wrapping a secp256k1 point.
     *
     * Fixed byte strings rather than a DER builder: they never vary, and the
     * only thing that changes is the point appended to them.
     */
    private const SPKI_COMPRESSED = '3036301006072a8648ce3d020106052b8104000a032200';
    private const SPKI_UNCOMPRESSED = '3056301006072a8648ce3d020106052b8104000a034200';

    /**
     * An EC private key with the optional public-key field omitted.
     *
     * Omitted on purpose: OpenSSL derives the public key from the scalar, so a
     * bare 32 bytes is enough and no point decompression is needed to load a
     * key stored in compressed form.
     */
    private const EC_PRIVATE_PREFIX = '302e0201010420';
    private const EC_PRIVATE_SUFFIX = 'a00706052b8104000a';

    /** secp256k1's group order, big-endian. */
    private const ORDER_HEX = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';

    private function __construct(
        private readonly string $publicRaw,
        private readonly ?string $privateRaw,
    ) {
    }

    // -- construction -----------------------------------------------------

    /**
     * Generates a key pair.
     *
     * Compressed by default: 33 bytes rather than 65, and this key is written
     * into a transaction and then stored on an identity stream permanently.
     *
     * @throws \RuntimeException if OpenSSL has no secp256k1 support
     */
    public static function generate(bool $compressed = true): self
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'secp256k1',
        ]);

        if ($key === false) {
            throw new \RuntimeException(
                'Could not generate a secp256k1 key. This PHP build\'s OpenSSL does not '
                . 'support the curve: ' . (openssl_error_string() ?: 'no detail given')
            );
        }

        $details = openssl_pkey_get_details($key);
        $scalar = self::pad($details['ec']['d']);

        return new self(
            self::encodePoint($details['ec']['x'], $details['ec']['y'], $compressed),
            $scalar
        );
    }

    /** A verify-only key pair from a stored public key. */
    public static function fromPublicKey(string $publicKey): self
    {
        $raw = self::decodeHex($publicKey, 'public');
        self::checkPublic($raw);

        return new self($raw, null);
    }

    /** Restores a signing key pair from stored key material. */
    public static function fromKeys(string $publicKey, string $privateKey): self
    {
        $public = self::decodeHex($publicKey, 'public');
        self::checkPublic($public);

        $scalar = self::decodeHex($privateKey, 'private');
        if (strlen($scalar) !== self::PRIVATE_KEY_SIZE) {
            throw new \InvalidArgumentException(sprintf(
                'secp256k1 private key is %d bytes, expected %d',
                strlen($scalar),
                self::PRIVATE_KEY_SIZE
            ));
        }

        return new self($public, $scalar);
    }

    // -- accessors --------------------------------------------------------

    public function keyType(): KeyType
    {
        return KeyType::Secp256k1;
    }

    /** The public key, 0x-prefixed hex, exactly as the ledger stores it. */
    public function publicKey(): string
    {
        return '0x' . bin2hex($this->publicRaw);
    }

    /**
     * The private scalar, 0x-prefixed hex, always 32 bytes.
     *
     * Left-padded: a value that dropped a leading zero byte — which happens to
     * roughly one key in 400 — is a different scalar to anything that reads it
     * strictly.
     */
    public function privateKey(): string
    {
        if ($this->privateRaw === null) {
            throw new \LogicException(
                'This key pair has no private key - it was created for verification only'
            );
        }

        return '0x' . bin2hex($this->privateRaw);
    }

    public function canSign(): bool
    {
        return $this->privateRaw !== null;
    }

    // -- signing ----------------------------------------------------------

    /**
     * Signs a message, always emitting a low-S signature.
     *
     * OpenSSL does not normalise S, so it is folded here. That is not for the
     * ledger, which accepts either, but for everything else: `@noble/curves`
     * rejects high-S unless explicitly told not to and is the reference for
     * the JavaScript side, libsecp256k1 rejects it outright, and Rust's
     * `k256` rejects it too. A signer emitting high-S roughly half the time
     * fails against those roughly half the time, which reads as flakiness
     * rather than as a signature format problem.
     *
     * NOT deterministic - see the class docblock. Signing the same message
     * twice gives different bytes, both valid.
     */
    public function sign(string $message): string
    {
        if ($this->privateRaw === null) {
            throw new \LogicException(
                'This key pair has no private key - it was created for verification only'
            );
        }

        $key = openssl_pkey_get_private($this->privatePem());
        if ($key === false) {
            throw new \RuntimeException(
                'OpenSSL rejected the private key: ' . (openssl_error_string() ?: 'no detail')
            );
        }

        $signature = '';
        if (!openssl_sign($message, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException(
                'Signing failed: ' . (openssl_error_string() ?: 'no detail given')
            );
        }

        return self::toLowS($signature);
    }

    /**
     * Verifies a signature, accepting HIGH-S as well as low.
     *
     * The ledger verifies through OpenSSL, which neither normalises nor
     * requires low-S, so roughly half of everything it produces is high-S.
     * This SDK uses the same OpenSSL, so it is permissive for free — which is
     * the correct behaviour, not an accident worth changing. A verifier that
     * rejected high-S would fail on about half of all valid signatures, and
     * the half that succeeded would make it look like an intermittent fault.
     *
     * Returns false rather than throwing for malformed input.
     */
    public function verify(string $message, string $signature): bool
    {
        $key = openssl_pkey_get_public($this->publicPem());
        if ($key === false) {
            return false;
        }

        // openssl_verify returns 1, 0 or -1; only 1 means valid. It also emits
        // a warning for malformed DER, which is not a caller's problem.
        return @openssl_verify($message, $signature, $key, OPENSSL_ALGO_SHA256) === 1;
    }

    // -- low S ------------------------------------------------------------

    /** Whether a DER signature's S is in the upper half of the curve order. */
    public static function isHighS(string $signature): bool
    {
        [, $s] = self::decodeDer($signature);

        return self::compare($s, self::halfOrder()) > 0;
    }

    /** Folds S into the lower half of the order, re-encoding the DER. */
    private static function toLowS(string $signature): string
    {
        [$r, $s] = self::decodeDer($signature);

        if (self::compare($s, self::halfOrder()) <= 0) {
            return $signature;
        }

        return self::encodeDer($r, self::subtract(hex2bin(self::ORDER_HEX), $s));
    }

    /**
     * @return array{0: string, 1: string} r and s, each left-padded to 32 bytes
     */
    private static function decodeDer(string $signature): array
    {
        if (strlen($signature) < 8 || $signature[0] !== "\x30") {
            throw new \InvalidArgumentException('signature is not a DER sequence');
        }

        $offset = 2;
        if ($signature[$offset] !== "\x02") {
            throw new \InvalidArgumentException('DER signature has no R component');
        }
        $rLength = ord($signature[$offset + 1]);
        $r = substr($signature, $offset + 2, $rLength);

        $offset += 2 + $rLength;
        if ($signature[$offset] !== "\x02") {
            throw new \InvalidArgumentException('DER signature has no S component');
        }
        $sLength = ord($signature[$offset + 1]);
        $s = substr($signature, $offset + 2, $sLength);

        return [self::pad($r), self::pad($s)];
    }

    private static function encodeDer(string $r, string $s): string
    {
        $body = self::derInteger($r) . self::derInteger($s);

        return "\x30" . chr(strlen($body)) . $body;
    }

    /**
     * A DER INTEGER: minimal length, and a leading zero byte when the top bit
     * is set so the value is not read as negative.
     */
    private static function derInteger(string $value): string
    {
        $value = ltrim($value, "\0");
        if ($value === '') {
            $value = "\0";
        }
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\0" . $value;
        }

        return "\x02" . chr(strlen($value)) . $value;
    }

    /**
     * n >> 1, the low/high S boundary.
     *
     * Computed byte-wise because this PHP build may have neither GMP nor
     * bcmath, and requiring either for one shift would be a poor trade.
     */
    private static function halfOrder(): string
    {
        static $half = null;
        if ($half !== null) {
            return $half;
        }

        $order = hex2bin(self::ORDER_HEX);
        $half = '';
        $carry = 0;
        for ($i = 0; $i < strlen($order); $i++) {
            $byte = ord($order[$i]);
            $half .= chr((($carry << 8) | $byte) >> 1);
            $carry = $byte & 1;
        }

        return $half;
    }

    /** Big-endian comparison of two equal-length byte strings. */
    private static function compare(string $a, string $b): int
    {
        return strcmp($a, $b);
    }

    /** Big-endian subtraction, a - b, both 32 bytes. */
    private static function subtract(string $a, string $b): string
    {
        $out = str_repeat("\0", self::PRIVATE_KEY_SIZE);
        $borrow = 0;

        for ($i = self::PRIVATE_KEY_SIZE - 1; $i >= 0; $i--) {
            $diff = ord($a[$i]) - ord($b[$i]) - $borrow;
            if ($diff < 0) {
                $diff += 256;
                $borrow = 1;
            } else {
                $borrow = 0;
            }
            $out[$i] = chr($diff);
        }

        return $out;
    }

    // -- encodings --------------------------------------------------------

    private function publicPem(): string
    {
        $prefix = strlen($this->publicRaw) === self::PUBLIC_KEY_COMPRESSED_SIZE
            ? self::SPKI_COMPRESSED
            : self::SPKI_UNCOMPRESSED;

        return self::pem('PUBLIC KEY', hex2bin($prefix) . $this->publicRaw);
    }

    private function privatePem(): string
    {
        return self::pem(
            'EC PRIVATE KEY',
            hex2bin(self::EC_PRIVATE_PREFIX) . $this->privateRaw . hex2bin(self::EC_PRIVATE_SUFFIX)
        );
    }

    private static function pem(string $label, string $der): string
    {
        return "-----BEGIN $label-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END $label-----\n";
    }

    private static function encodePoint(string $x, string $y, bool $compressed): string
    {
        $x = self::pad($x);
        $y = self::pad($y);

        if (!$compressed) {
            return "\x04" . $x . $y;
        }

        // 0x02 for an even y, 0x03 for odd.
        $prefix = (ord($y[strlen($y) - 1]) & 1) === 0 ? "\x02" : "\x03";

        return $prefix . $x;
    }

    /** Left-pads a big-endian value to 32 bytes. */
    private static function pad(string $value): string
    {
        $value = ltrim($value, "\0");

        return str_pad($value, self::PRIVATE_KEY_SIZE, "\0", STR_PAD_LEFT);
    }

    /**
     * Decodes an 0x-prefixed hex key.
     *
     * The prefix is required rather than tolerated: it is part of what the
     * ledger stores, and a hex string without it can decode as base64 into
     * plausible-looking bytes of the wrong length.
     */
    private static function decodeHex(string $value, string $role): string
    {
        if (!str_starts_with($value, '0x')) {
            throw new \InvalidArgumentException(
                "secp256k1 $role key must start with '0x' - that prefix is part of what "
                . 'the ledger stores, not decoration. Post-quantum keys are base64; '
                . 'these are not.'
            );
        }

        $body = substr($value, 2);
        if (strlen($body) % 2 !== 0 || !ctype_xdigit($body)) {
            throw new \InvalidArgumentException("secp256k1 $role key is not valid hex");
        }

        return (string) hex2bin($body);
    }

    /** Checks the length and that the SEC1 point prefix agrees with it. */
    private static function checkPublic(string $raw): void
    {
        if (strlen($raw) === self::PUBLIC_KEY_COMPRESSED_SIZE) {
            $compressed = true;
        } elseif (strlen($raw) === self::PUBLIC_KEY_UNCOMPRESSED_SIZE) {
            $compressed = false;
        } else {
            throw new \InvalidArgumentException(sprintf(
                'secp256k1 public key is %d bytes, expected %d (compressed) or %d (uncompressed)',
                strlen($raw),
                self::PUBLIC_KEY_COMPRESSED_SIZE,
                self::PUBLIC_KEY_UNCOMPRESSED_SIZE
            ));
        }

        $prefix = ord($raw[0]);
        $ok = $compressed ? ($prefix === 0x02 || $prefix === 0x03) : $prefix === 0x04;

        if (!$ok) {
            throw new \InvalidArgumentException(sprintf(
                'secp256k1 public key starts with 0x%02x, which does not match its length '
                . 'of %d bytes (expected 0x02/0x03 for %d, 0x04 for %d)',
                $prefix,
                strlen($raw),
                self::PUBLIC_KEY_COMPRESSED_SIZE,
                self::PUBLIC_KEY_UNCOMPRESSED_SIZE
            ));
        }
    }
}

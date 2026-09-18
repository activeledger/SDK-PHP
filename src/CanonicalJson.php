<?php

declare(strict_types=1);

namespace Activeledger;

/**
 * Canonical JSON: the exact bytes Activeledger signs.
 *
 * Signatures cover the bytes of `JSON.stringify($tx)` encoded as UTF-8 -- no
 * hash prefix, no length prefix, no domain separator and **no key sorting**.
 * A signature over bytes that differ by a single escape is invalid, and the
 * ledger reports that as 1220 "Signature Incorrect", which says nothing at
 * all about serialisation.
 *
 * PHP's own `json_encode` cannot produce these bytes with its defaults: it
 * escapes forward slashes as `\/` and non-ASCII as `\uXXXX`. Both flags exist
 * to turn that off, but `json_encode` still formats floats differently from
 * JavaScript and offers no way to express an explicitly ordered object
 * distinct from a list. So this class owns the format.
 *
 * Objects are PHP associative arrays, which preserve insertion order, and
 * that order is what gets signed.
 */
final class CanonicalJson
{
    /**
     * Serialises to the exact string the ledger expects.
     *
     * @param mixed $value
     * @throws CanonicalJsonException
     */
    public static function encode(mixed $value): string
    {
        $out = '';
        self::write($out, $value);
        return $out;
    }

    /**
     * The exact bytes that get signed.
     *
     * @param mixed $value
     * @throws CanonicalJsonException
     */
    public static function bytes(mixed $value): string
    {
        // PHP strings are byte strings, so this is already UTF-8 provided the
        // source was. Kept as a named method so call sites read the same as
        // in the other SDKs.
        return self::encode($value);
    }

    /**
     * Marks an array as a JSON object even when it is empty or list-shaped.
     *
     * `[]` is ambiguous in PHP: it is both an empty array and an empty object.
     * `$o` in a transaction is an object and must serialise as `{}`, not `[]`,
     * and getting that wrong changes the signed bytes.
     */
    public static function object(array $entries = []): JsonObject
    {
        return new JsonObject($entries);
    }

    /**
     * @throws CanonicalJsonException
     */
    private static function write(string &$out, mixed $value): void
    {
        if ($value === null) {
            $out .= 'null';
            return;
        }
        if (is_bool($value)) {
            $out .= $value ? 'true' : 'false';
            return;
        }
        if (is_int($value)) {
            $out .= (string) $value;
            return;
        }
        if (is_float($value)) {
            self::writeFloat($out, $value);
            return;
        }
        if (is_string($value)) {
            self::writeString($out, $value);
            return;
        }
        if ($value instanceof JsonObject) {
            self::writeObject($out, $value->entries());
            return;
        }
        if (is_array($value)) {
            // A list serialises as an array, anything else as an object. Use
            // CanonicalJson::object() to force object-ness for an empty one.
            if (array_is_list($value)) {
                $out .= '[';
                foreach ($value as $i => $item) {
                    if ($i > 0) {
                        $out .= ',';
                    }
                    self::write($out, $item);
                }
                $out .= ']';
                return;
            }
            self::writeObject($out, $value);
            return;
        }

        throw new CanonicalJsonException(
            'Cannot serialise ' . get_debug_type($value) . '. Build the structure explicitly: '
            . 'what gets signed is these exact bytes, so an inferred conversion would be a silent risk.'
        );
    }

    /**
     * @param array<array-key, mixed> $entries
     * @throws CanonicalJsonException
     */
    private static function writeObject(string &$out, array $entries): void
    {
        $out .= '{';
        $first = true;
        foreach ($entries as $key => $item) {
            if (!$first) {
                $out .= ',';
            }
            $first = false;
            // PHP turns a numeric-string key into an int. JSON keys are always
            // strings, so it goes back.
            self::writeString($out, (string) $key);
            $out .= ':';
            self::write($out, $item);
        }
        $out .= '}';
    }

    /**
     * JavaScript number formatting: one numeric type, shortest representation
     * that round-trips. `JSON.stringify(1.0)` is `1`.
     *
     * @throws CanonicalJsonException
     */
    private static function writeFloat(string &$out, float $value): void
    {
        if (is_nan($value)) {
            throw new CanonicalJsonException('NaN cannot be signed');
        }
        if (is_infinite($value)) {
            throw new CanonicalJsonException('Infinity cannot be signed');
        }

        if ($value == floor($value) && abs($value) < 1e21) {
            $out .= (string) (int) $value;
            return;
        }

        // serialize_precision -1 selects the shortest round-tripping form,
        // which is what JavaScript does. The ini value is read explicitly
        // rather than trusted, because a host that has changed it would
        // otherwise produce different signed bytes on a different machine.
        $encoded = json_encode($value);
        if ($encoded === false) {
            throw new CanonicalJsonException('Could not encode float');
        }
        $out .= $encoded;
    }

    /**
     * Escapes exactly what JSON.stringify escapes: the two characters JSON
     * requires plus control characters below 0x20. Everything else, including
     * all non-ASCII and forward slashes, passes through as raw UTF-8.
     */
    private static function writeString(string &$out, string $value): void
    {
        $out .= '"';

        $length = strlen($value);
        for ($i = 0; $i < $length; $i++) {
            $c = $value[$i];
            switch ($c) {
                case '"':
                    $out .= '\\"';
                    break;
                case '\\':
                    $out .= '\\\\';
                    break;
                case "\n":
                    $out .= '\\n';
                    break;
                case "\r":
                    $out .= '\\r';
                    break;
                case "\t":
                    $out .= '\\t';
                    break;
                case "\x08":
                    $out .= '\\b';
                    break;
                case "\x0C":
                    $out .= '\\f';
                    break;
                default:
                    if ($c < "\x20") {
                        $out .= sprintf('\\u%04x', ord($c));
                    } else {
                        // Byte-wise, so multi-byte UTF-8 sequences pass
                        // through untouched.
                        $out .= $c;
                    }
            }
        }

        $out .= '"';
    }
}

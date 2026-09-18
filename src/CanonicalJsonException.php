<?php

declare(strict_types=1);

namespace Activeledger;

/** A value that cannot be represented in the bytes the ledger signs. */
final class CanonicalJsonException extends \RuntimeException
{
}

<?php

declare(strict_types=1);

namespace Zbkm\Siwe;

use Random\RandomException;

/**
 * NonceManager
 */
class NonceManager
{
    /**
     * Generate random nonce string
     *
     * @return string A randomly generated EIP-4361 nonce
     * @throws RandomException
     */
    public static function generate(): string
    {
        return bin2hex(random_bytes(16));
    }
}

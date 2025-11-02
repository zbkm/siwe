<?php

declare(strict_types=1);

namespace Zbkm\Siwe\Ethereum;

use Elliptic\EC;
use kornrunner\Keccak;
use Zbkm\Siwe\Exception\SignatureException;

/**
 * Ethereum signatures
 */
class Signature
{
    /**
     * Ethereum personal_sign prefix from eip-191
     */
    public const MESSAGE_PREFIX = "\x19Ethereum Signed Message:\n";

    /**
     * Verify personal sign message
     *
     * @param $message   string Message without "Ethereum Signed Message" prefix
     * @param $signature string Signature
     * @param $address   string Signer address
     * @return bool
     * @throws SignatureException
     */
    public static function verifyMessage(string $message, string $signature, string $address): bool
    {
        $msglen = strlen($message);
        $message = self::MESSAGE_PREFIX . "{$msglen}{$message}";

        $signer = self::ecrecover($message, $signature);
        return strtolower($address) == $signer;
    }

    /**
     * Return signer address from message and signature
     *
     * @param string $message   Message
     * @param string $signature Signature
     * @return string
     * @throws SignatureException
     */
    public static function ecrecover(string $message, string $signature): string
    {
        $hash = Keccak::hash($message, 256);

        $sign = [
            "r" => substr($signature, 2, 64),
            "s" => substr($signature, 66, 64)
        ];
        $v = hexdec(substr($signature, 130, 2)) - 27;

        if ($v != ($v & 1)) {
            throw new SignatureException("v can only be 27 or 28");
        }

        return self::pubKeyToAddress(
            (new EC('secp256k1'))
                ->recoverPubKey($hash, $sign, $v)
                ->encode("hex")
        );
    }

    /**
     * Format hex pubkey to Ethereum address
     *
     * @param string $pubkey
     * @return string
     * @throws \Exception
     */
    protected static function pubKeyToAddress(string $pubkey): string
    {
        return "0x" . substr(Keccak::hash(substr(hex2bin($pubkey), 1), 256), 24);
    }
}

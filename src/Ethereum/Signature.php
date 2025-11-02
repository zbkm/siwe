<?php

declare(strict_types=1);

namespace Zbkm\Siwe\Ethereum;

use Elliptic\Curve\BaseCurve\Point;
use Elliptic\EC;
use Exception;
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
     * @throws Exception
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
     * @throws Exception
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

        /** @var Point $point */
        $point = (new EC('secp256k1'))->recoverPubKey($hash, $sign, $v);

        /** @var string $pubkey */
        $pubkey = $point->encode("hex");

        return self::pubKeyToAddress($pubkey);
    }

    /**
     * Format hex pubkey to Ethereum address
     *
     * @param string $pubkey
     * @return string
     * @throws Exception
     */
    protected static function pubKeyToAddress(string $pubkey): string
    {
        // @phpstan-ignore-next-line EC will definitely return the pubkey in hex format
        return "0x" . substr(Keccak::hash(substr(hex2bin($pubkey), 1), 256), 24);
    }
}

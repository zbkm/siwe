<?php
declare(strict_types=1);

use Zbkm\Siwe\SiweMessage;
use PHPUnit\Framework\TestCase;
use Zbkm\Siwe\SiweMessageParams;

class SiweMessageVerifyTest extends TestCase
{
    public function testVerifyDefault()
    {
        $message = new SiweMessageParams(
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            chainId: 1,
            domain: "example.com",
            uri: "https://example.com/path",
            issuedAt: new DateTime("2023-01-31T19:00:00.000Z"),
            nonce: "foobarbaz",
            version: "1"
        );

        $this->assertTrue(
            SiweMessage::verify($message, "0xbcf74ace618c839ca98e02dd56a214656f8ae981dcb0bc5199a9ef76a73a8c642a3d029b2b867a982c2f101c87701b5df129a40dfeee081b3e3bc1fe11a9a5521b")
        );
    }

    public function testVerifyInvalidMessageFields()
    {
        $message = new SiweMessageParams(
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            chainId: 1,
            domain: "viem.sh",
            uri: "https://example.com/path",
            issuedAt: new DateTime("2023-02-01T00:00:00.000Z"),
            nonce: "foobarbaz",
            version: "1"
        );

        $this->assertFalse(
            SiweMessage::verify($message, "0xbcf74ace618c839ca98e02dd56a214656f8ae981dcb0bc5199a9ef76a73a8c642a3d029b2b867a982c2f101c87701b5df129a40dfeee081b3e3bc1fe11a9a5521b")
        );
    }
}

<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Zbkm\Siwe\Exception\SiweValidateException;
use Zbkm\Siwe\SiweMessage;
use Zbkm\Siwe\SiweMessageParams;

class SiweMessageValidateTest extends TestCase
{
    public function testValidate(): void
    {
        $params = new SiweMessageParams(
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            chainId: 1,
            domain: "example.com",
            uri: "https://example.com/path",
            issuedAt: new DateTime("2023-01-31T19:00:00.000Z"),
            nonce: "foobarbaz",
            version: "1",
        );

        $this->assertTrue(SiweMessage::validate($params, []));
        $this->assertTrue(SiweMessage::validate($params, [
            "nonce" => "foobarbaz",
            "domain" => "example.com",
        ]));
    }

    public function testInvalidValidate(): void
    {
        $params = new SiweMessageParams(
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            chainId: 1,
            domain: "example.com",
            uri: "https://example.com/path",
            issuedAt: new DateTime("2023-01-31T19:00:00.000Z"),
            nonce: "foobarbaz",
            version: "1",
        );

        $this->assertFalse(SiweMessage::validate($params, [
            "nonce" => "foobarbaz",
            "domain" => "not-valid-field",
        ]));

        $this->assertFalse(SiweMessage::validate($params, [
            "not-exist-field" => "foobarbaz",
        ]));
    }

    public function testValidateExcept(): void
    {
        $params = new SiweMessageParams(
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            chainId: 1,
            domain: "example.com",
            uri: "https://example.com/path",
            issuedAt: new DateTime("2023-01-31T19:00:00.000Z"),
            nonce: "foobarbaz",
            version: "1",
        );

        $this->assertTrue(SiweMessage::validateOrFail($params, [
            "nonce" => "foobarbaz",
        ]));

        $this->expectException(SiweValidateException::class);
        $this->expectExceptionMessage(
            "Invalid validate Sign-In with Ethereum message field \"requestId\"

Provided value:
Excepted value: not-exist-field",
        );
        $this->assertFalse(SiweMessage::validateOrFail($params, [
            "requestId" => "not-exist-field",
        ]));


        $this->expectException(SiweValidateException::class);
        $this->expectExceptionMessage("Invalid validate Sign-In with Ethereum message field \"domain\"

Provided value: example.com
Excepted value: not-valid-field");
        $this->assertFalse(SiweMessage::validateOrFail($params, [
            "domain" => "not-valid-field",
        ]));
    }
}

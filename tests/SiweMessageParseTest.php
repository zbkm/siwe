<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Zbkm\Siwe\SiweMessage;
use Zbkm\Siwe\SiweMessageParams;

// tests from https://github.com/wevm/viem/blob/main/src/utils/siwe/parseSiweMessage.test.ts

class SiweMessageParseTest extends TestCase
{
    public function testParseDefault()
    {
        $message = "example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

I accept the ExampleOrg Terms of Service: https://example.com/tos

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z";

        $result = SiweMessageParams::fromArray([
            "address" => "0xA0Cf798816D4b9b9866b5330EEa46a18382f251e",
            "chainId" => 1,
            "domain" => "example.com",
            "issuedAt" => new DateTime("2023-02-01T00:00:00.000Z"),
            "nonce" => "foobarbaz",
            "statement" => "I accept the ExampleOrg Terms of Service: https://example.com/tos",
            "uri" => "https://example.com/path",
            "version" => "1",
        ]);

        $this->assertEquals($result, SiweMessage::parse($message));
    }

    public function testParseWithDomainPort()
    {
        $message = "example.com:8080 wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z";

        $this->assertEquals("example.com:8080", SiweMessage::parse($message)->domain);
    }

    public function testParseWithStatement()
    {
        $message = "example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

I accept the ExampleOrg Terms of Service: https://example.com/tos

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z";

        $this->assertEquals(
            "I accept the ExampleOrg Terms of Service: https://example.com/tos",
            SiweMessage::parse($message)->statement
        );
    }

    public function testParseWithExpirationTime()
    {
        $message = "https://example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Expiration Time: 2022-02-04T00:00:00.000Z";

        $this->assertEquals(
            new DateTime("2022-02-04T00:00:00.000Z"),
            SiweMessage::parse($message)->expirationTime
        );
    }

    public function testParseWithNotBefore()
    {
        $message = "https://example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Not Before: 2022-02-04T00:00:00.000Z";

        $this->assertEquals(
            new DateTime("2022-02-04T00:00:00.000Z"),
            SiweMessage::parse($message)->notBefore
        );
    }

    public function testParseWithRequestId()
    {
        $message = "https://example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Request ID: 123e4567-e89b-12d3-a456-426614174000";

        $this->assertEquals(
            "123e4567-e89b-12d3-a456-426614174000",
            SiweMessage::parse($message)->requestId
        );
    }

    public function testParseWithResources()
    {
        $message = "https://example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Resources:
- https://example.com/foo
- https://example.com/bar
- https://example.com/baz";

        $this->assertEquals(
            [
                "https://example.com/foo",
                "https://example.com/bar",
                "https://example.com/baz"
            ],
            SiweMessage::parse($message)->resources
        );
    }

    public function testParseWithTimeMilliseconds()
    {
        $message = "https://example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.500Z";

        $this->assertNotEquals(
            new DateTime("2023-02-01T00:00:00.800Z"),
            SiweMessage::parse($message)->issuedAt
        );
        $this->assertEquals(
            new DateTime("2023-02-01T00:00:00.500Z"),
            SiweMessage::parse($message)->issuedAt
        );
    }
}

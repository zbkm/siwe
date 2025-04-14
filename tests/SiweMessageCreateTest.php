<?php
declare(strict_types=1);

use Zbkm\Siwe\Exception\SiweInvalidMessageFieldException;
use Zbkm\Siwe\SiweMessage;
use PHPUnit\Framework\TestCase;
use Zbkm\Siwe\SiweMessageParamsBuilder;

class SiweMessageCreateTest extends TestCase
{
    protected SiweMessageParamsBuilder $messageBuilder;

    function setUp(): void
    {
        $this->messageBuilder = SiweMessageParamsBuilder::create()
            ->withAddress('0xA0Cf798816D4b9b9866b5330EEa46a18382f251e')
            ->withChainId(1)
            ->withDomain('example.com')
            ->withNonce('foobarbaz')
            ->withUri('https://example.com/path')
            ->withIssuedAt(new DateTime('2023-02-01T00:00:00.000Z'))
            ->withVersion('1');
    }

    public function testCreateDefault()
    {
        // mock time() function
        eval('
            namespace Zbkm\Siwe; 

            function time(): int {
                return 1675209600;
            }
        ');

        $message = SiweMessage::create($this->messageBuilder->build());
        $this->assertSame("example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z",
            $message);
    }

    public function testCreateWithDomain()
    {
        $message = SiweMessage::create($this->messageBuilder->withDomain("foo.example.com")->build());
        $this->assertSame("foo.example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z",
            $message);

        $message = SiweMessage::create($this->messageBuilder->withDomain("example.co.uk")->build());
        $this->assertSame("example.co.uk wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z",
            $message);
    }

    public function testCreateWithScheme()
    {
        $message = SiweMessage::create($this->messageBuilder->withScheme("https")->build());
        $this->assertSame("https://example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z",
            $message);
    }

    public function testCreateWithStatement()
    {
        $message = SiweMessage::create(
            $this->messageBuilder
                ->withStatement("I accept the ExampleOrg Terms of Service: https://example.com/tos")->build()
        );
        $this->assertSame("example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e

I accept the ExampleOrg Terms of Service: https://example.com/tos

URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z",
            $message);
    }

    public function testCreateWithIssuedAt()
    {

        $message = SiweMessage::create($this
            ->messageBuilder
            ->withIssuedAt((new DateTime())->setDate(2022, 2, 1)->setTime(0, 0))
            ->build());
        $this->assertSame("example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2022-02-01T00:00:00.000Z",
            $message);
    }

    public function testCreateWithExpirationTime()
    {
        $message = SiweMessage::create($this
            ->messageBuilder
            ->withExpirationTime((new DateTime())->setDate(2022, 2, 4)->setTime(0, 0))
            ->build());
        $this->assertSame("example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Expiration Time: 2022-02-04T00:00:00.000Z",
            $message);
    }

    public function testCreateWithNotBefore()
    {
        $message = SiweMessage::create($this
            ->messageBuilder
            ->withNotBefore((new DateTime())->setDate(2022, 2, 4)->setTime(0, 0))
            ->build());

        $this->assertSame("example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Not Before: 2022-02-04T00:00:00.000Z",
            $message);
    }

    public function testCreateWithRequestId()
    {
        $message = SiweMessage::create(
            $this->messageBuilder
                ->withRequestId("123e4567-e89b-12d3-a456-426614174000")
                ->build()
        );

        $this->assertSame("example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Request ID: 123e4567-e89b-12d3-a456-426614174000",
            $message);
    }

    public function testCreateWithResources()
    {
        $message = SiweMessage::create($this->messageBuilder->withResources([
            "https://example.com/foo",
            "https://example.com/bar",
            "https://example.com/baz",
        ])->build());

        $this->assertSame("example.com wants you to sign in with your Ethereum account:
0xA0Cf798816D4b9b9866b5330EEa46a18382f251e


URI: https://example.com/path
Version: 1
Chain ID: 1
Nonce: foobarbaz
Issued At: 2023-02-01T00:00:00.000Z
Resources:
- https://example.com/foo
- https://example.com/bar
- https://example.com/baz",
            $message);
    }

    public function testExceptCreateWithInvalidAddress()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"address\".

- Address must be a hex value of 20 bytes (40 hex characters).
- Address must match its checksum counterpart.

Provided value: 0xfoobarbaz");
        SiweMessage::create($this->messageBuilder->withAddress("0xfoobarbaz")->build());

    }

    public function testExceptCreateWithInvalidChainId()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"chainId\".

- Chain ID must be a EIP-155 chain ID.
- See https://eips.ethereum.org/EIPS/eip-155

Provided value: -5");
        SiweMessage::create($this->messageBuilder->withChainId(-5)->build());
    }

    public function testExceptCreateWithInvalidDomain()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"domain\".

- Domain must be an RFC 3986 authority.
- See https://www.rfc-editor.org/rfc/rfc3986

Provided value: #foo");
        SiweMessage::create($this->messageBuilder->withDomain("#foo")->build());
    }

    public function testExceptCreateWithInvalidNonce()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"nonce\".

- Nonce must be at least 8 characters.
- Nonce must be alphanumeric.

Provided value: #foo");
        SiweMessage::create($this->messageBuilder->withNonce("#foo")->build());
    }

    public function testExceptCreateWithInvalidUri()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"uri\".

- URI must be a RFC 3986 URI referring to the resource that is the subject of the signing.
- See https://www.rfc-editor.org/rfc/rfc3986

Provided value: #foo");
        SiweMessage::create($this->messageBuilder->withUri("#foo")->build());
    }

    public function testExceptCreateWithInvalidVersion()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"version\".

- Version must be '1'.

Provided value: 2");
        SiweMessage::create($this->messageBuilder->withVersion("2")->build());
    }

    public function testExceptCreateWithInvalidScheme()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"scheme\".

- Scheme must be an RFC 3986 URI scheme.
- See https://www.rfc-editor.org/rfc/rfc3986#section-3.1

Provided value: foo_bar");
        SiweMessage::create($this->messageBuilder->withScheme("foo_bar")->build());
    }

    public function testExceptCreateWithInvalidStatement()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"statement\".

- Statement must not include '\\n'.

Provided value: foo
bar");
        SiweMessage::create($this->messageBuilder->withStatement("foo\nbar")->build());
    }

    public function testExceptCreateWithInvalidResource()
    {
        $this->expectException(SiweInvalidMessageFieldException::class);
        $this->expectExceptionMessage("Invalid Sign-In with Ethereum message field \"resources\".

- Every resource must be a RFC 3986 URI.
- See https://www.rfc-editor.org/rfc/rfc3986

Provided value: foo");
        SiweMessage::create($this->messageBuilder->withResources(["https://example.com", "foo"])->build());
    }
}

<?php

declare(strict_types=1);

namespace Zbkm\Siwe;

use DateTime;
use DateTimeInterface;
use Random\RandomException;
use Zbkm\Siwe\Validators\SiweMessageFieldValidator;

/**
 * SiweMessageParams
 * @description fields representation in siwe message
 */
class SiweMessageParams
{
    public const DEFAULT_VERSION = "1";
    public string $address;
    public int $chainId;
    public string $domain;
    public string $uri;
    public DateTimeInterface $issuedAt;
    public string $nonce;
    public ?string $statement;
    public ?string $version;
    public ?string $scheme;
    public ?DateTimeInterface $expirationTime;
    public ?DateTimeInterface $notBefore;
    public ?string $requestId;
    /**
     * @var string[]
     */
    public ?array $resources;


    /**
     * @param string             $address        The Ethereum address performing the signing
     * @param int                $chainId        Chain ID (1 for Ethereum)
     * @param string             $domain         The domain that is requesting the signing
     * @param string             $uri            An RFC 3986 URI referring to the resource that is the subject of the signing (as in the subject of a claim)
     * @param ?DateTimeInterface $issuedAt       The time when the message was generated, typically the current time. Default: now
     * @param ?string            $nonce          A random string typically chosen by the relying party and used to prevent replay attacks, at least 8 alphanumeric characters. Default: random
     * @param ?string            $statement      A human-readable ASCII assertion that the user will sign which MUST NOT include "\n"
     * @param ?string            $version        The current version of the SIWE Message, which MUST be 1 for this specification
     * @param ?string            $scheme         The URI scheme of the origin of the request
     * @param ?DateTimeInterface $expirationTime The time when the signed authentication message is no longer valid
     * @param ?DateTimeInterface $notBefore      The time when the signed authentication message will become valid
     * @param ?string            $requestId      A system-specific identifier that MAY be used to uniquely refer to the sign-in request
     * @param ?string[]          $resources      A list of information or references to information the user wishes to have resolved as part of authentication by the relying party
     * @throws RandomException
     */
    public function __construct(
        string             $address,
        int                $chainId,
        string             $domain,
        string             $uri,
        ?DateTimeInterface $issuedAt = null,
        ?string            $nonce = null,
        ?string            $statement = null,
        ?string            $version = null,
        ?string            $scheme = null,
        ?DateTimeInterface $expirationTime = null,
        ?DateTimeInterface $notBefore = null,
        ?string            $requestId = null,
        ?array             $resources = null,
    ) {
        $this->address = $address;
        $this->chainId = $chainId;
        $this->domain = $domain;
        $this->uri = $uri;
        $this->issuedAt = $issuedAt ?? new DateTime();
        $this->nonce = $nonce ?? NonceManager::generate();
        $this->statement = $statement;
        $this->version = $version ?? self::DEFAULT_VERSION;
        $this->scheme = $scheme;
        $this->expirationTime = $expirationTime;
        $this->notBefore = $notBefore;
        $this->requestId = $requestId;
        $this->resources = $resources;

        $this->validate();
    }

    /**
     * Create Message Params from assoc array
     *
     * @param array{
     *      address: string,
     *      chainId: int,
     *      domain: string,
     *      uri: string,
     *      issuedAt?: DateTimeInterface,
     *      nonce?: string,
     *      statement?: string,
     *      version?: string,
     *      scheme?: string,
     *      expirationTime?: DateTimeInterface,
     *      notBefore?: DateTimeInterface,
     *      requestId?: string,
     *      resources?: string[]
     *     } $data
     * @return SiweMessageParams
     * @throws RandomException
     */
    public static function fromArray(array $data): self
    {
        return new self(
            address: $data["address"],
            chainId: $data["chainId"],
            domain: $data["domain"],
            uri: $data["uri"],
            issuedAt: $data["issuedAt"] ?? null,
            nonce: $data["nonce"] ?? null,
            statement: $data["statement"] ?? null,
            version: $data["version"] ?? null,
            scheme: $data["scheme"] ?? null,
            expirationTime: $data["expirationTime"] ?? null,
            notBefore: $data["notBefore"] ?? null,
            requestId: $data["requestId"] ?? null,
            resources: $data["resources"] ?? null,
        );
    }

    /**
     * Validate params
     *
     * @return void
     */
    protected function validate(): void
    {
        SiweMessageFieldValidator::validateOrFail($this);
    }
}

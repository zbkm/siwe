<?php

declare(strict_types=1);

namespace Zbkm\Siwe;

use DateTimeInterface;
use Zbkm\Siwe\Exception\SiweInvalidMessageFieldException;

class SiweMessageParamsBuilder
{
    protected string $address;
    protected int $chainId;
    protected string $domain;
    protected ?string $statement = null;
    protected ?DateTimeInterface $expirationTime = null;
    protected ?DateTimeInterface $issuedAt = null;
    protected ?DateTimeInterface $notBefore = null;
    protected ?string $requestId = null;
    protected ?string $scheme = null;
    protected ?string $nonce = null;
    protected string $uri;
    protected ?string $version = null;
    protected ?array $resources = null;

    protected function __construct()
    {
    }

    /**
     * @return self
     */
    public static function create(): self
    {
        return new self();
    }

    /**
     * @param string $address The Ethereum address performing the signing
     * @return $this
     */
    public function withAddress(string $address): self
    {
        $this->address = $address;
        return $this;
    }

    /**
     * @param int $chainId Chain ID (1 for Ethereum)
     * @return $this
     */
    public function withChainId(int $chainId): self
    {
        $this->chainId = $chainId;
        return $this;
    }

    /**
     * @param string $domain The domain that is requesting the signing
     * @return $this
     */
    public function withDomain(string $domain): self
    {
        $this->domain = $domain;
        return $this;
    }

    /**
     * @param string $statement A human-readable ASCII assertion that the user will sign which MUST NOT include '\n'
     * @return $this
     */
    public function withStatement(string $statement): self
    {
        $this->statement = $statement;
        return $this;
    }

    /**
     * @param DateTimeInterface $expirationTime The time when the signed authentication message is no longer valid
     * @return $this
     */
    public function withExpirationTime(DateTimeInterface $expirationTime): self
    {
        $this->expirationTime = $expirationTime;
        return $this;
    }

    /**
     * @param DateTimeInterface $issuedAt The time when the message was generated, typically the current time
     * @return $this
     */
    public function withIssuedAt(DateTimeInterface $issuedAt): self
    {
        $this->issuedAt = $issuedAt;
        return $this;
    }

    /**
     * @param DateTimeInterface $notBefore The time when the signed authentication message will become valid
     * @return $this
     */
    public function withNotBefore(DateTimeInterface $notBefore): self
    {
        $this->notBefore = $notBefore;
        return $this;
    }

    /**
     * @param string $requestId A system-specific identifier that MAY be used to uniquely refer to the sign-in request
     * @return $this
     */
    public function withRequestId(string $requestId): self
    {
        $this->requestId = $requestId;
        return $this;
    }

    /**
     * @param string $scheme The URI scheme of the origin of the request
     * @return $this
     */
    public function withScheme(string $scheme): self
    {
        $this->scheme = $scheme;
        return $this;
    }

    /**
     * @param string $nonce A random string typically chosen by the relying party and used to prevent replay attacks, at least 8 alphanumeric characters
     * @return $this
     */
    public function withNonce(string $nonce): self
    {
        $this->nonce = $nonce;
        return $this;
    }

    /**
     * @param string $uri An RFC 3986 URI referring to the resource that is the subject of the signing (as in the subject of a claim)
     * @return $this
     */
    public function withUri(string $uri): self
    {
        $this->uri = $uri;
        return $this;
    }

    /**
     * @param string $version The current version of the SIWE Message, which MUST be 1 for this specification
     * @return $this
     */
    public function withVersion(string $version): self
    {
        $this->version = $version;
        return $this;
    }

    /**
     * @param array $resources A list of information or references to information the user wishes to have resolved as part of authentication by the relying party
     * @return $this
     */
    public function withResources(array $resources): self
    {
        $this->resources = $resources;
        return $this;
    }

    /**
     * Create Params for transfers to SiweMessage class
     *
     * @return SiweMessageParams
     * @throws \Random\RandomException
     */
    public function build(): SiweMessageParams
    {
        $requiredFields = ['address', 'chainId', 'domain', 'uri'];

        foreach ($requiredFields as $field) {
            if (!isset($this->$field)) {
                throw new SiweInvalidMessageFieldException($field, "", ["Required fields are not set"]);
            }
        }

        return new SiweMessageParams(
            address: $this->address,
            chainId: $this->chainId,
            domain: $this->domain,
            uri: $this->uri,
            issuedAt: $this->issuedAt,
            nonce: $this->nonce,
            statement: $this->statement,
            version: $this->version,
            scheme: $this->scheme,
            expirationTime: $this->expirationTime,
            notBefore: $this->notBefore,
            requestId: $this->requestId,
            resources: $this->resources
        );
    }
}

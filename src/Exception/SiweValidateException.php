<?php

declare(strict_types=1);

namespace Zbkm\Siwe\Exception;

use RuntimeException;

/**
 * SiweValidateException
 */
class SiweValidateException extends RuntimeException
{
    protected string $field;
    protected string|int|null $providedValue;
    protected string|int|null $exceptedValue;

    /**
     * @param string          $field         field name
     * @param string|int|null $providedValue provided value
     * @param string|int|null $exceptedValue excepted value
     */
    public function __construct(
        string          $field,
        string|int|null $providedValue,
        string|int|null $exceptedValue,
    ) {
        $message = "Invalid validate Sign-In with Ethereum message field \"$field\"\n";
        $message .= "\nProvided value:" . ($providedValue ? " $providedValue" : "");
        $message .= "\nExcepted value: $exceptedValue";

        parent::__construct($message);

        $this->field = $field;
        $this->providedValue = $providedValue;
        $this->exceptedValue = $exceptedValue;
    }

    /**
     * Get field name
     *
     * @return string
     */
    public function getField(): string
    {
        return $this->field;
    }

    /**
     * Get excepted value
     *
     * @return string|int|null
     */
    public function getExceptedValue(): string|int|null
    {
        return $this->exceptedValue;
    }

    /**
     * Get provided value
     *
     * @return string|int|null
     */
    public function getProvidedValue(): string|int|null
    {
        return $this->providedValue;
    }
}

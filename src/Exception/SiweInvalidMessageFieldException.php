<?php

declare(strict_types=1);

namespace Zbkm\Siwe\Exception;

use RuntimeException;

/**
 * SiweInvalidMessageFieldException
 */
class SiweInvalidMessageFieldException extends RuntimeException
{
    protected string $field;
    protected string|int|null $value;

    /**
     * @param string          $field field name
     * @param string|int|null $value field value
     * @param string[]        $conditions unmet conditions
     */
    public function __construct(
        string          $field,
        string|int|null $value,
        array           $conditions,
    ) {
        $message = "Invalid Sign-In with Ethereum message field \"$field\".\n";
        foreach ($conditions as $condition) {
            $message .= "\n- $condition";
        };
        $message .= "\n\nProvided value: {$value}";

        parent::__construct($message);
        $this->field = $field;
        $this->value = $value;
    }

    /**
     * Get invalid message field name
     *
     * @return string
     */
    public function getField(): string
    {
        return $this->field;
    }

    /**
     * Get invalid message field value
     *
     * @return string|int|null
     */
    public function getValue(): string|int|null
    {
        return $this->value;
    }
}

<?php

declare(strict_types=1);

namespace Zbkm\Siwe\Exception;

use RuntimeException;

class SiweInvalidMessageFieldException extends RuntimeException
{
    protected string $field;
    protected string|int $value;

    public function __construct(
        string          $field,
        string|int $value,
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

    public function getField(): string
    {
        return $this->field;
    }

    public function getValue(): string|int
    {
        return $this->value;
    }
}

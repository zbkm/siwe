<?php

declare(strict_types=1);

namespace Zbkm\Siwe\Utils;

use DateTime;
use DateTimeInterface;
use Zbkm\Siwe\Exception\SiweTimeException;

/**
 * TimeFormatter
 * @description helper for formatting time
 */
class TimeFormatter
{
    /**
     * Convert DateTimeInterface to time string in ISO format
     * @param DateTimeInterface $datetime
     * @return string ISO format time string
     */
    public static function datetimeToISO(DateTimeInterface $datetime): string
    {
        return $datetime->format("Y-m-d\TH:i:s.v\Z");
    }

    /**
     * Convert ISO time string to DateTime
     * @param string $iso time string in ISO format
     * @return DateTime
     * @throws SiweTimeException
     */
    public static function ISOToDatetime(string $iso): DateTime
    {
        $time = DateTime::createFromFormat("Y-m-d\TH:i:s.v\Z", $iso);
        if ($time === false) {
            throw new SiweTimeException();
        }
        return $time;
    }
}

<?php

declare(strict_types=1);

namespace Zbkm\Siwe\Utils;

use DateTime;
use DateTimeInterface;
use Zbkm\Siwe\Exception\SiweTimeException;

class TimeFormatter
{
    public static function datetimeToISO(DateTimeInterface $datetime): string
    {
        return $datetime->format('Y-m-d\TH:i:s.v\Z');
    }

    public static function ISOToDatetime(string $iso): DateTime
    {
        $time = DateTime::createFromFormat('Y-m-d\TH:i:s.v\Z', $iso);
        if ($time === false) {
            throw new SiweTimeException();
        }
        return $time;
    }
}

<?php
declare(strict_types=1);

namespace Zbkm\Siwe\Utils;

use DateTime;
use DateTimeInterface;

class TimeFormatter
{
    public static function datetimeToISO(DateTimeInterface $datetime): string
    {
        return $datetime->format('Y-m-d\TH:i:s.v\Z');
    }

    public static function ISOToDatetime(string $iso): DateTime
    {
        return DateTime::createFromFormat('Y-m-d\TH:i:s.v\Z', $iso);
    }
}
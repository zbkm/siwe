<?php

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__)
    ->exclude(["var"]);

return (new PhpCsFixer\Config())
    ->setCacheFile(__DIR__ . "/var/cache/.php-cs-fixer.cache")
    ->setRules([
        "@PSR12" => true
    ])
    ->setFinder($finder);
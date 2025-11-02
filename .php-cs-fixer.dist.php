<?php

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__)
    ->exclude(["var"]);

return (new PhpCsFixer\Config())
    ->setParallelConfig(PhpCsFixer\Runner\Parallel\ParallelConfigFactory::detect())
    ->setCacheFile(__DIR__ . "/var/cache/.php-cs-fixer.cache")
    ->setRules([
        "@PER-CS" => true,
        "@PER-CS:risky" => true,
    ])
    ->setRiskyAllowed(true)
    ->setFinder($finder);
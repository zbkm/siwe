<?php

use PHPUnit\Framework\TestCase;
use Zbkm\Siwe\NonceManager;

class NonceManagerTest extends TestCase
{
    public function testGenerateNonce(): void
    {
        $nonce = NonceManager::generate();
        $this->assertSame(32, strlen($nonce));

        $nonce2 = NonceManager::generate();
        $this->assertNotSame($nonce, $nonce2);
    }
}

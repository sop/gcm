<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\GCM\Cipher\AES\AES128Cipher;
use Sop\GCM\Cipher\AES\AESCipher;

/**
 * @group cipher
 * @group aes
 *
 * @internal
 */
class AESCipherTest extends TestCase
{
    public function testInvalidKeySizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        AESCipher::fromKeyLength(0);
    }

    public function testEncryptionFail()
    {
        $cipher = new AES128Cipher();
        $this->expectException(\RuntimeException::class);
        $cipher->encrypt('fail', '0123456789abcdef');
    }
}

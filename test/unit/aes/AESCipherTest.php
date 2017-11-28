<?php

use PHPUnit\Framework\TestCase;
use Sop\GCM\Cipher\AES\AES128Cipher;
use Sop\GCM\Cipher\AES\AESCipher;

/**
 * @group cipher
 * @group aes
 */
class AESCipherTest extends TestCase
{
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidKeySizeFail()
    {
        AESCipher::fromKeyLength(0);
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testEncryptionFail()
    {
        $cipher = new AES128Cipher();
        $cipher->encrypt("fail", "0123456789abcdef");
    }
}

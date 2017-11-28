<?php

use PHPUnit\Framework\TestCase;
use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Cipher\AES\AES128Cipher;
use Sop\GCM\Cipher\AES\AESCipher;

/**
 * @group cipher
 * @group aes
 */
class AES128CipherTest extends TestCase
{
    const KEY = "0123456789abcdef";
    
    const DATA = "deadbeeffacefeed";
    
    public function testCreate()
    {
        $cipher = AESCipher::fromKeyLength(strlen(self::KEY));
        $this->assertInstanceOf(AES128Cipher::class, $cipher);
        return $cipher;
    }
    
    /**
     * @depends testCreate
     *
     * @param Cipher $cipher
     */
    public function testEncrypt(Cipher $cipher)
    {
        $ciphertext = $cipher->encrypt(self::DATA, self::KEY);
        $this->assertInternalType("string", $ciphertext);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidKeySize()
    {
        $cipher = new AES128Cipher();
        $cipher->encrypt(self::DATA, "fail");
    }
}

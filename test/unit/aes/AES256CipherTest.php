<?php

use GCM\Cipher\Cipher;
use GCM\Cipher\AES\AES256Cipher;
use GCM\Cipher\AES\AESCipher;
use PHPUnit\Framework\TestCase;

/**
 * @group cipher
 * @group aes
 */
class AES256CipherTest extends TestCase
{
    const KEY = "0123456789abcdef0123456789abcdef";
    
    const DATA = "deadbeeffacefeed";
    
    public function testCreate()
    {
        $cipher = AESCipher::fromKeyLength(strlen(self::KEY));
        $this->assertInstanceOf(AES256Cipher::class, $cipher);
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
        $cipher = new AES256Cipher();
        $cipher->encrypt(self::DATA, "fail");
    }
}

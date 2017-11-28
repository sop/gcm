<?php

use GCM\Cipher\Cipher;
use GCM\Cipher\AES\AES192Cipher;
use GCM\Cipher\AES\AESCipher;
use PHPUnit\Framework\TestCase;

/**
 * @group cipher
 * @group aes
 */
class AES192CipherTest extends TestCase
{
    const KEY = "0123456789abcdef01234567";
    
    const DATA = "deadbeeffacefeed";
    
    public function testCreate()
    {
        $cipher = AESCipher::fromKeyLength(strlen(self::KEY));
        $this->assertInstanceOf(AES192Cipher::class, $cipher);
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
        $cipher = new AES192Cipher();
        $cipher->encrypt(self::DATA, "fail");
    }
}

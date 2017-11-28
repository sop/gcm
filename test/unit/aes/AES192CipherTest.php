<?php

use PHPUnit\Framework\TestCase;
use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Cipher\AES\AES192Cipher;
use Sop\GCM\Cipher\AES\AESCipher;

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

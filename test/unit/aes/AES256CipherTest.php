<?php

use PHPUnit\Framework\TestCase;
use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Cipher\AES\AES256Cipher;
use Sop\GCM\Cipher\AES\AESCipher;

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

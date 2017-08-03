<?php

use GCM\GCM;
use GCM\Cipher\AES\AES128Cipher;

/**
 * @group gcm
 */
class GCMTest extends PHPUnit_Framework_TestCase
{
    const PLAINTEXT = "My hovercraft is full of eels.";
    
    const AAD = "Ahh, matches!";
    
    const KEY = "0123456789abcdef";
    
    const IV = "fedcba987654";
    
    public function testCreate()
    {
        $gcm = new GCM(new AES128Cipher());
        $this->assertInstanceOf(GCM::class, $gcm);
        return $gcm;
    }
    
    /**
     * @depends testCreate
     *
     * @param GCM $gcm
     */
    public function testEncrypt(GCM $gcm)
    {
        $result = $gcm->encrypt(self::PLAINTEXT, self::AAD, self::KEY, self::IV);
        $this->assertContainsOnly("string", $result);
        return $result;
    }
    
    /**
     * @depends testEncrypt
     *
     * @param array $result
     */
    public function testCiphertext($result)
    {
        $ciphertext = $result[0];
        $this->assertNotEquals(self::PLAINTEXT, $ciphertext);
        $this->assertEquals(strlen(self::PLAINTEXT), strlen($ciphertext));
    }
    
    /**
     * @depends testEncrypt
     *
     * @param array $result
     */
    public function testAuthenticationTag($result)
    {
        $auth_tag = $result[1];
        $this->assertInternalType("string", $auth_tag);
        $this->assertEquals(16, strlen($auth_tag));
    }
    
    /**
     * @depends testCreate
     * @depends testEncrypt
     *
     * @param GCM $gcm
     * @param array $result
     */
    public function testDecrypt(GCM $gcm, $result)
    {
        $plaintext = $gcm->decrypt($result[0], $result[1], self::AAD, self::KEY,
            self::IV);
        $this->assertEquals(self::PLAINTEXT, $plaintext);
    }
    
    /**
     * @depends testCreate
     * @depends testEncrypt
     * @expectedException GCM\Exception\AuthenticationException
     *
     * @param GCM $gcm
     * @param array $result
     */
    public function testDecryptAuthFail(GCM $gcm, $result)
    {
        $gcm->decrypt($result[0], "fail", self::AAD, self::KEY, self::IV);
    }
    
    /**
     * @depends testCreate
     *
     * @param GCM $gcm
     */
    public function testEncryptCustomIV(GCM $gcm)
    {
        $result = $gcm->encrypt(self::PLAINTEXT, self::AAD, self::KEY, "iv");
        $this->assertContainsOnly("string", $result);
    }
    
    /**
     * @depends testCreate
     *
     * @param GCM $gcm
     */
    public function testEncryptEmptyData(GCM $gcm)
    {
        $result = $gcm->encrypt("", self::AAD, self::KEY, self::IV);
        $this->assertContainsOnly("string", $result);
    }
    
    /**
     * @expectedException DomainException
     */
    public function testUnsupportedTagLengthFail()
    {
        new GCM(new AES128Cipher(), 17);
    }
    
    public function testCustomTagLength()
    {
        $gcm = new GCM(new AES128Cipher(), 8);
        list($ciphertext, $auth_tag) = $gcm->encrypt("", "", self::KEY, "");
        $this->assertEquals(8, strlen($auth_tag));
    }
    
    public function testIncWrap()
    {
        $cls = new ReflectionClass(GCM::class);
        $mtd = $cls->getMethod("_inc32");
        $mtd->setAccessible(true);
        $ctr = $mtd->invoke(null, hex2bin("ffffffffff"));
        $this->assertEquals(hex2bin("ff00000000"), $ctr);
    }
}

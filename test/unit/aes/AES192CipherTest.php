<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\GCM\Cipher\AES\AES192Cipher;
use Sop\GCM\Cipher\AES\AESCipher;
use Sop\GCM\Cipher\Cipher;

/**
 * @group cipher
 * @group aes
 *
 * @internal
 */
class AES192CipherTest extends TestCase
{
    const KEY = '0123456789abcdef01234567';

    const DATA = 'deadbeeffacefeed';

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
        $this->assertIsString($ciphertext);
    }

    public function testInvalidKeySize()
    {
        $cipher = new AES192Cipher();
        $this->expectException(\UnexpectedValueException::class);
        $cipher->encrypt(self::DATA, 'fail');
    }
}

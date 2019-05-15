<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\GCM\Cipher\AES\AES128Cipher;
use Sop\GCM\Cipher\AES\AESCipher;
use Sop\GCM\Exception\AuthenticationException;

/**
 * @group cipher
 * @group aes
 *
 * @internal
 */
class AESCipherTest extends TestCase
{
    const KEY_128 = '0123456789abcdef';

    public function testInvalidKeySizeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        AESCipher::fromKeyLength(0);
    }

    public function testEncryptionFail()
    {
        $cipher = new AES128Cipher();
        $this->expectException(\RuntimeException::class);
        $cipher->encrypt('fail', self::KEY_128);
    }

    public function testNativeEncryptFail()
    {
        $cipher = new FailCipher();
        $this->expectException(\RuntimeException::class);
        $cipher->nativeEncrypt('', '', self::KEY_128, self::KEY_128);
    }

    public function testNativeDecryptFail()
    {
        $cipher = new AES128Cipher();
        [$ciphertext, $tag] = $cipher->nativeEncrypt('test', '', self::KEY_128, self::KEY_128);
        $this->expectException(AuthenticationException::class);
        $cipher->nativeDecrypt($ciphertext, '', '', self::KEY_128, self::KEY_128);
    }
}

class FailCipher extends AESCipher
{
    protected function _cipherName(): string
    {
        return 'invalid';
    }

    protected function _nativeCipherName(): string
    {
        return 'invalid';
    }

    protected function _keySize(): int
    {
        return 16;
    }
}

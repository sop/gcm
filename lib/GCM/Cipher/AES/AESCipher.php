<?php

declare(strict_types = 1);

namespace Sop\GCM\Cipher\AES;

use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Exception\AuthenticationException;

/**
 * Base class for AES ciphers for the GCM.
 */
abstract class AESCipher implements Cipher
{
    /**
     * Mapping from key size in bits to AES cipher implementation class name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_KEYSIZE_TO_CLS = [
        128 => AES128Cipher::class,
        192 => AES192Cipher::class,
        256 => AES256Cipher::class,
    ];

    /**
     * Get AES cipher instance by key length.
     *
     * @param int $len Key length in bytes
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromKeyLength(int $len): self
    {
        $bits = $len << 3;
        if (!array_key_exists($bits, self::MAP_KEYSIZE_TO_CLS)) {
            throw new \UnexpectedValueException(
                "No AES implementation for {$bits}-bit key size.");
        }
        $cls = self::MAP_KEYSIZE_TO_CLS[$bits];
        return new $cls();
    }

    /**
     * {@inheritdoc}
     *
     * @throws \UnexpectedValueException If key size is incorrect
     * @throws \RuntimeException         For generic errors
     */
    public function encrypt(string $data, string $key): string
    {
        $this->_checkKeySize($key);
        $result = openssl_encrypt($data, $this->_cipherName(), $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if (false === $result) {
            throw new \RuntimeException(
                'openssl_encrypt() failed: ' . self::_getLastOpenSSLError());
        }
        return $result;
    }

    /**
     * Check whether OpenSSL has native AES-GCM cipher available.
     *
     * @return bool
     */
    public function hasNativeCipher(): bool
    {
        static $supported_methods;
        if (!isset($supported_methods)) {
            $supported_methods = array_flip(openssl_get_cipher_methods(false));
        }
        $method = $this->_nativeCipherName();
        return isset($supported_methods[$method]);
    }

    /**
     * Encrypt plaintext using native OpenSSL.
     *
     * @param string $plaintext  Plaintext to encrypt
     * @param string $aad        Additional authenticated data
     * @param string $key        Encryption key
     * @param string $iv         Initialization vector
     * @param int    $tag_length Authentication tag length in bytes
     *
     * @return array Tuple of ciphertext and authentication tag
     */
    public function nativeEncrypt(string $plaintext, string $aad, string $key,
        string $iv, int $tag_length = 16): array
    {
        $this->_checkKeySize($key);
        $ciphertext = @openssl_encrypt($plaintext, $this->_nativeCipherName(),
            $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv, $tag, $aad, $tag_length);
        // should never fail, since key size is already checked
        if (false === $ciphertext) {
            throw new \RuntimeException(
                'openssl_encrypt() failed: ' . self::_getLastOpenSSLError());
        }
        return [$ciphertext, $tag];
    }

    /**
     * Decrypt ciphertext using native OpenSSL.
     *
     * @param string $ciphertext Ciphertext to decrypt
     * @param string $auth_tag   Authentication tag to verify
     * @param string $aad        Additional authenticated data
     * @param string $key        Encryption key
     * @param string $iv         Initialization vector
     *
     * @return string Plaintext
     */
    public function nativeDecrypt(string $ciphertext, string $auth_tag,
        string $aad, string $key, string $iv): string
    {
        $this->_checkKeySize($key);
        $plaintext = openssl_decrypt($ciphertext, $this->_nativeCipherName(),
            $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv, $auth_tag, $aad);
        if (false === $plaintext) {
            throw new AuthenticationException('Authentication failed.');
        }
        return $plaintext;
    }

    /**
     * Get the AES-ECB cipher method name recognized by OpenSSL.
     *
     * @return string
     */
    abstract protected function _cipherName(): string;

    /**
     * Get the AES-GCM cipher method recognized by OpenSSL.
     */
    abstract protected function _nativeCipherName(): string;

    /**
     * Get the key size in bytes.
     *
     * @return int
     */
    abstract protected function _keySize(): int;

    protected function _checkKeySize(string $key): void
    {
        if (strlen($key) !== $this->_keySize()) {
            throw new \UnexpectedValueException('Key size must be ' .
                $this->_keySize() . ' bytes.');
        }
    }

    /**
     * Get latest OpenSSL error message.
     *
     * @return string
     */
    protected static function _getLastOpenSSLError(): string
    {
        $msg = '';
        while (false !== ($err = openssl_error_string())) {
            $msg = $err;
        }
        return $msg;
    }
}

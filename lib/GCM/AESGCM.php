<?php

declare(strict_types = 1);

namespace Sop\GCM;

use Sop\GCM\Cipher\AES\AESCipher;

/**
 * Implements AES-GCM encryption.
 */
abstract class AESGCM
{
    /**
     * Encrypt plaintext.
     *
     * @param string $plaintext  Plaintext to encrypt
     * @param string $aad        Additional authenticated data
     * @param string $key        Encryption key
     * @param string $iv         Initialization vector
     * @param int    $tag_length Authentication tag length in bytes
     *
     * @return array Tuple of ciphertext and authentication tag
     */
    public static function encrypt(string $plaintext, string $aad, string $key,
        string $iv, int $tag_length = 16): array
    {
        $cipher = AESCipher::fromKeyLength(strlen($key));
        if ($cipher->hasNativeCipher()) {
            return $cipher->nativeEncrypt($plaintext, $aad, $key, $iv, $tag_length);
        }
        return self::_getGCM($cipher, $tag_length)
            ->encrypt($plaintext, $aad, $key, $iv);
    }

    /**
     * Decrypt ciphertext.
     *
     * @param string $ciphertext Ciphertext to decrypt
     * @param string $auth_tag   Authentication tag to verify
     * @param string $aad        Additional authenticated data
     * @param string $key        Encryption key
     * @param string $iv         Initialization vector
     *
     * @throws \Sop\GCM\Exception\AuthenticationException If message authentication fails
     *
     * @return string Plaintext
     */
    public static function decrypt(string $ciphertext, string $auth_tag,
        string $aad, string $key, string $iv): string
    {
        $cipher = AESCipher::fromKeyLength(strlen($key));
        if ($cipher->hasNativeCipher()) {
            return $cipher->nativeDecrypt($ciphertext, $auth_tag, $aad, $key, $iv);
        }
        return self::_getGCM($cipher, strlen($auth_tag))
            ->decrypt($ciphertext, $auth_tag, $aad, $key, $iv);
    }

    /**
     * Get GCM instance.
     *
     * @param AESCipher $cipher     Cipher instance
     * @param int       $tag_length Authentication tag length
     *
     * @return GCM
     */
    protected static function _getGCM(AESCipher $cipher, int $tag_length): GCM
    {
        return new GCM($cipher, $tag_length);
    }
}

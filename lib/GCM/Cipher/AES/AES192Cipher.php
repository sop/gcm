<?php

declare(strict_types = 1);

namespace Sop\GCM\Cipher\AES;

/**
 * Implements AES cipher with 192-bit key size.
 */
class AES192Cipher extends AESCipher
{
    /**
     * {@inheritdoc}
     */
    protected function _cipherName(): string
    {
        return 'aes-192-ecb';
    }

    /**
     * {@inheritdoc}
     */
    protected function _nativeCipherName(): string
    {
        return 'aes-192-gcm';
    }

    /**
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 24;
    }
}

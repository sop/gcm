<?php

declare(strict_types = 1);

namespace Sop\GCM\Cipher\AES;

/**
 * Implements AES cipher with 128-bit key size.
 */
class AES128Cipher extends AESCipher
{
    /**
     * {@inheritdoc}
     */
    protected function _cipherName(): string
    {
        return 'aes-128-ecb';
    }

    /**
     * {@inheritdoc}
     */
    protected function _nativeCipherName(): string
    {
        return 'aes-128-gcm';
    }

    /**
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 16;
    }
}

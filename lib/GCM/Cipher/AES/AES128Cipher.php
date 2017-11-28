<?php

declare(strict_types = 1);

namespace GCM\Cipher\AES;

/**
 * Implements AES cipher with 128-bit key size.
 */
class AES128Cipher extends AESCipher
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _cipherName(): string
    {
        return "AES-128-ECB";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 16;
    }
}

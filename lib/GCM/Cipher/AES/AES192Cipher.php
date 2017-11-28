<?php

declare(strict_types = 1);

namespace GCM\Cipher\AES;

/**
 * Implements AES cipher with 192-bit key size.
 */
class AES192Cipher extends AESCipher
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _cipherName(): string
    {
        return "AES-192-ECB";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 24;
    }
}

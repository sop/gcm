<?php

declare(strict_types = 1);

namespace Sop\GCM\Cipher\AES;

/**
 * Implements AES cipher with 256-bit key size.
 */
class AES256Cipher extends AESCipher
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _cipherName(): string
    {
        return "AES-256-ECB";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 32;
    }
}

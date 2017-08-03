<?php

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
    protected function _cipherName()
    {
        return "AES-128-ECB";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize()
    {
        return 16;
    }
}

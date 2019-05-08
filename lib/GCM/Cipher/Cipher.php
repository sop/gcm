<?php

declare(strict_types = 1);

namespace Sop\GCM\Cipher;

/**
 * Interface for ciphers usable for GCM.
 */
interface Cipher
{
    /**
     * Encrypt data.
     *
     * @param string $data Data to encrypt
     * @param string $key  Encryption key
     *
     * @return string Encrypted data
     */
    public function encrypt(string $data, string $key): string;
}

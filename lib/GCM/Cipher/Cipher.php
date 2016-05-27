<?php

namespace GCM\Cipher;


/**
 * Interface for ciphers usable for GCM.
 */
interface Cipher
{
	/**
	 * Encrypt data.
	 *
	 * @param string $data Data to encrypt
	 * @param string $key Encryption key
	 * @return string Encrypted data
	 */
	public function encrypt($data, $key);
}

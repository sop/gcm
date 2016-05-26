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
	 * @param string $data
	 * @param string $key
	 * @return string
	 */
	public function encrypt($data, $key);
}

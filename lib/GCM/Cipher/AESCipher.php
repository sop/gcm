<?php

namespace GCM\Cipher;


/**
 * Implements AES cipher for the GCM.
 */
class AESCipher implements Cipher
{
	const AES_KEY_SIZES = [128, 192, 256];
	
	public function encrypt($data, $key) {
		$keysize = strlen($key) << 3;
		if (!in_array($keysize, self::AES_KEY_SIZES)) {
			throw new \UnexpectedValueException(
				"Invalid key size for AES encryption.");
		}
		$method = "AES-$keysize-ECB";
		$result = openssl_encrypt($data, $method, $key, 
			OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
		return $result;
	}
}

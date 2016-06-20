<?php

namespace GCM\Cipher\AES;

use GCM\Cipher\Cipher;


/**
 * Base class for AES ciphers for the GCM.
 */
abstract class AESCipher implements Cipher
{
	/**
	 * Mapping from key size in bits to AES cipher implementation class name.
	 *
	 * @internal
	 *
	 * @var array
	 */
	const MAP_KEYSIZE_TO_CLS = array(
		/* @formatter:off */
		128 => AES128Cipher::class,
		192 => AES192Cipher::class,
		256 => AES256Cipher::class
		/* @formatter:on */
	);
	
	/**
	 * Get the cipher method name recognized by OpenSSL.
	 *
	 * @return string
	 */
	abstract protected function _cipherName();
	
	/**
	 * Get the key size in bytes.
	 *
	 * @return int
	 */
	abstract protected function _keySize();
	
	/**
	 * Get AES cipher instance by key length.
	 *
	 * @param int $len Key length in bytes
	 * @throws \UnexpectedValueException
	 * @return self
	 */
	public static function fromKeyLength($len) {
		$bits = $len << 3;
		if (!array_key_exists($bits, self::MAP_KEYSIZE_TO_CLS)) {
			throw new \UnexpectedValueException(
				"No AES implementation for $bits-bit key size.");
		}
		$cls = self::MAP_KEYSIZE_TO_CLS[$bits];
		return new $cls();
	}
	
	/**
	 *
	 * @see \GCM\Cipher\Cipher::encrypt()
	 * @throws \UnexpectedValueException If key size is incorrect
	 * @throws \RuntimeException For generic errors
	 * @return string
	 */
	public function encrypt($data, $key) {
		$key_size = $this->_keySize();
		if (strlen($key) != $key_size) {
			throw new \UnexpectedValueException(
				"Key size must be $key_size bytes.");
		}
		$result = openssl_encrypt($data, $this->_cipherName(), $key, 
			OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
		if (false === $result) {
			throw new \RuntimeException(
				"openssl_encrypt() failed: " . self::_getLastOpenSSLError());
		}
		return $result;
	}
	
	/**
	 * Get latest OpenSSL error message.
	 *
	 * @return string
	 */
	protected static function _getLastOpenSSLError() {
		$msg = null;
		while (false !== ($err = openssl_error_string())) {
			$msg = $err;
		}
		return $msg;
	}
}

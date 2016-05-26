<?php

namespace GCM;

use GCM\Cipher\AESCipher;


/**
 * Implements AES-GCM encryption.
 */
abstract class AESGCM
{
	/**
	 * Encrypt plaintext.
	 *
	 * @param string $plaintext Plaintext to encrypt
	 * @param string $aad Additional authenticated data
	 * @param string $key Encryption key
	 * @param string $iv Initialization vector
	 * @return array Tuple of ciphertext and authentication tag
	 */
	public static function encrypt($plaintext, $aad, $key, $iv) {
		$gcm = new GCM(new AESCipher());
		return $gcm->encrypt($plaintext, $aad, $key, $iv);
	}
	
	/**
	 * Decrypt ciphertext.
	 *
	 * @param string $ciphertext Ciphertext to decrypt
	 * @param string $auth_tag Authentication tag to verify
	 * @param string $aad Additional authenticated data
	 * @param string $key Encryption key
	 * @param string $iv Initialization vector
	 * @return string Plaintext
	 */
	public static function decrypt($ciphertext, $auth_tag, $aad, $key, $iv) {
		$gcm = new GCM(new AESCipher());
		return $gcm->decrypt($ciphertext, $auth_tag, $aad, $key, $iv);
	}
}

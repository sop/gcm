<?php

namespace GCM\Cipher\AES;


/**
 * Implements AES cipher with 192-bit key size.
 */
class AES192Cipher extends AESCipher
{
	protected function _cipherName() {
		return "AES-192-ECB";
	}
}

<?php

namespace GCM\Cipher\AES;


/**
 * Implements AES cipher with 256-bit key size.
 */
class AES256Cipher extends AESCipher
{
	protected function _cipherName() {
		return "AES-256-ECB";
	}
}

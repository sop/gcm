<?php

namespace GCM\Cipher\AES;


/**
 * Implements AES cipher with 128-bit key size.
 */
class AES128Cipher extends AESCipher
{
	protected function _cipherName() {
		return "AES-128-ECB";
	}
}

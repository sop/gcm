<?php

use GCM\Cipher\AES\AES128Cipher;
use GCM\Cipher\AES\AESCipher;


class AESCipherTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @expectedException UnexpectedValueException
	 */
	public function testInvalidKeySizeFail() {
		AESCipher::fromKeyLength(0);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testEncryptionFail() {
		$cipher = new AES128Cipher();
		$cipher->encrypt("fail", "");
	}
}

<?php

use GCM\Cipher\AES\AES128Cipher;
use GCM\Cipher\AES\AESCipher;
use GCM\Cipher\Cipher;


class AES128CipherTest extends PHPUnit_Framework_TestCase
{
	const KEY = "0123456789abcdef";
	
	const DATA = "deadbeeffacefeed";
	
	public function testCreate() {
		$cipher = AESCipher::fromKeyLength(strlen(self::KEY));
		$this->assertInstanceOf(AES128Cipher::class, $cipher);
		return $cipher;
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param Cipher $cipher
	 */
	public function testEncrypt(Cipher $cipher) {
		$ciphertext = $cipher->encrypt(self::DATA, self::KEY);
		$this->assertInternalType("string", $ciphertext);
	}
}

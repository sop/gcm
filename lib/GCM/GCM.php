<?php

namespace GCM;

use GCM\Cipher\Cipher;


/**
 * Implements encryption and decryption in Galois/Counter Mode.
 *
 * @link http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 */
class GCM
{
	/**
	 * Block of 64 zero bits.
	 *
	 * @var string
	 */
	const ZB_64 = "\0\0\0\0\0\0\0\0";
	
	/**
	 * Block of 128 zero bits.
	 *
	 * @var string
	 */
	const ZB_128 = self::ZB_64 . self::ZB_64;
	
	/**
	 * Cipher.
	 *
	 * @var Cipher $_cipher
	 */
	protected $_cipher;
	
	/**
	 * Constructor.
	 *
	 * @param Cipher $cipher
	 */
	public function __construct(Cipher $cipher) {
		$this->_cipher = $cipher;
	}
	
	/**
	 * Encrypt plaintext.
	 *
	 * @param string $P Plaintext
	 * @param string $A Additional authenticated data
	 * @param string $K Encryption key
	 * @param string $IV Initialization vector
	 * @return array Tuple of ciphertext <code>C</code> and authentication tag
	 *         <code>T</code>
	 */
	public function encrypt($P, $A, $K, $IV) {
		$ghash = new GHASH($this->_cipher->encrypt(self::ZB_128, $K));
		// generate pre-counter block
		$J0 = $this->_generateJ0($IV, $ghash);
		// encrypt
		$C = $this->_gctr(self::_inc32($J0), $P, $K);
		// generate authentication tag
		$T = $this->_computeAuthTag($A, $C, $J0, $K, $ghash);
		return [$C, $T];
	}
	
	/**
	 * Decrypt ciphertext.
	 *
	 * @param string $C Ciphertext
	 * @param string $T Authentication tag
	 * @param string $A Additional authenticated data
	 * @param string $K Encryption key
	 * @param string $IV Initialization vector
	 * @throws \UnexpectedValueException
	 * @return string Plaintext <code>P</code>
	 */
	public function decrypt($C, $T, $A, $K, $IV) {
		$ghash = new GHASH($this->_cipher->encrypt(self::ZB_128, $K));
		// generate pre-counter block
		$J0 = $this->_generateJ0($IV, $ghash);
		// generate authentication tag
		$T2 = $this->_computeAuthTag($A, $C, $J0, $K, $ghash);
		// check that authentication tag matches
		if ($T !== $T2) {
			throw new \UnexpectedValueException("Authentication failed.");
		}
		// decrypt
		return $this->_gctr(self::_inc32($J0), $C, $K);
	}
	
	/**
	 * Generate pre-counter block.
	 *
	 * @param string $IV Initialization vector
	 * @param GHASH $ghash GHASH functor
	 * @return string
	 */
	private function _generateJ0($IV, GHASH $ghash) {
		// if len(IV) = 96
		if (12 == strlen($IV)) {
			return $IV . "\0\0\0\1";
		}
		$data = self::_pad128($IV) . self::ZB_64 . self::_uint64(
			strlen($IV) << 3);
		return $ghash($data);
	}
	
	/**
	 * Apply GCTR algorithm.
	 *
	 * @param string $ICB Initial counter block
	 * @param string $X Input data
	 * @param string $K Encryption key
	 * @return string Output data
	 */
	private function _gctr($ICB, $X, $K) {
		// if data is an empty string, return an empty string
		if ("" == $X) {
			return "";
		}
		// number of blocks
		$n = ceil(strlen($X) / 16);
		$CB = $ICB;
		$Y = "";
		for ($i = 0; $i < $n - 1; ++$i) {
			// plaintext block
			$xi = substr($X, $i << 4, 16);
			// encrypt block and append to Y
			$Y .= $xi ^ $this->_cipher->encrypt($CB, $K);
			// increment counter block
			$CB = self::_inc32($CB);
		}
		// final block
		$xn = substr($X, $i << 4);
		// XOR against partial block
		$Y .= $xn ^ substr($this->_cipher->encrypt($CB, $K), 0, strlen($xn));
		return $Y;
	}
	
	/**
	 * Compute authentication tag
	 *
	 * @param string $A Additional authenticated data
	 * @param string $C Ciphertext
	 * @param string $J0 Pre-counter block
	 * @param string $K Encryption key
	 * @param GHASH $ghash GHASH functor
	 * @return string Authentication tag <code>T</code>
	 */
	private function _computeAuthTag($A, $C, $J0, $K, GHASH $ghash) {
		$data = self::_pad128($A) . self::_pad128($C) .
			 self::_uint64(strlen($A) << 3) . self::_uint64(strlen($C) << 3);
		$S = $ghash($data);
		return substr($this->_gctr($J0, $S, $K), 0, 16);
	}
	
	/**
	 * Pad data to 128 bit block boundary.
	 *
	 * @param string $data
	 * @return string
	 */
	private static function _pad128($data) {
		$padlen = 16 - strlen($data) % 16;
		if (16 != $padlen) {
			$data .= str_repeat("\0", $padlen);
		}
		return $data;
	}
	
	/**
	 * Increment 32 rightmost bits of the counter block.
	 *
	 * @param unknown $X
	 */
	private static function _inc32($X) {
		$Y = substr($X, 0, -4);
		// increment counter
		$n = self::strToGMP(substr($X, -4)) + 1;
		// wrap by using only the 32 rightmost bits
		$Y .= substr(self::gmpToStr($n, 4), -4);
		return $Y;
	}
	
	/**
	 * Convert integer to 64 bit big endian binary string.
	 *
	 * @param int $num
	 * @return string
	 */
	private static function _uint64($num) {
		// truncate on 32 bit hosts
		if (PHP_INT_SIZE < 8) {
			return "\0\0\0\0" . pack("N", $num);
		}
		return pack("J", $num);
	}
	
	/**
	 * Convert string to GMP number.
	 *
	 * String is interpreted as an unsigned integer with big endian order and
	 * the most significant byte first.
	 *
	 * @param string $data
	 * @return \GMP
	 */
	public static function strToGMP($data) {
		return gmp_import($data, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
	}
	
	/**
	 * Convert GMP number to string.
	 *
	 * Returned string represents an unsigned integer with big endian order and
	 * the most significant byte first.
	 *
	 * @param \GMP $num
	 * @param int $size Width of the string in bytes
	 * @return string
	 */
	public static function gmpToStr($num, $size) {
		$data = gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
		$len = strlen($data);
		if ($len < $size) {
			$data = str_repeat("\0", $size - $len) . $data;
		}
		return $data;
	}
}
<?php

namespace GCM;


/**
 * Implements GHASH function.
 *
 * @link http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 */
class GHASH
{
	/**
	 * Fixed R-block.
	 *
	 * @var string
	 */
	const R = "\xE1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	
	/**
	 * Hash subkey.
	 *
	 * @var string $_subkey
	 */
	protected $_subkey;
	
	/**
	 * Constructor.
	 *
	 * @param string $subkey Hash subkey
	 */
	public function __construct($subkey) {
		$this->_subkey = $subkey;
	}
	
	/**
	 * Compute hash.
	 *
	 * @param string $X
	 * @return string
	 */
	public function compute($X) {
		$len = strlen($X);
		if (0 != $len % 16) {
			throw new \UnexpectedValueException(
				"Input string must be a multiple of 128 bits.");
		}
		$Y = GCM::ZB_128;
		// number of 128-bit blocks
		$m = $len >> 4;
		for ($i = 0; $i < $m; ++$i) {
			$xi = substr($X, $i << 4, 16);
			$Y = $this->_mult($Y ^ $xi, $this->_subkey);
		}
		return $Y;
	}
	
	/**
	 * Functor method for <code>compute</code>.
	 *
	 * @param string $arg
	 * @return string
	 */
	public function __invoke($arg) {
		return $this->compute($arg);
	}
	
	/**
	 * Apply block multiplication operation.
	 *
	 * See NIST SP 800-38D, chapter 6.3 for details.
	 *
	 * @param string $X
	 * @param string $Y
	 * @return string
	 */
	private function _mult($X, $Y) {
		$x = GCM::strToGMP($X);
		$Z = GCM::strToGMP(GCM::ZB_128);
		$V = GCM::strToGMP($Y);
		$R = GCM::strToGMP(self::R);
		for ($i = 0; $i < 128; ++$i) {
			// if bit at X[i] is set
			if (gmp_testbit($x, 127 - $i)) {
				$Z ^= $V;
			}
			// if LSB(Vi) = 0
			if (!gmp_testbit($V, 0)) {
				$V >>= 1;
			} else {
				$V = ($V >> 1) ^ $R;
			}
		}
		return GCM::gmpToStr($Z, 16);
	}
}
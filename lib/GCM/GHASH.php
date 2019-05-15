<?php

declare(strict_types = 1);

namespace Sop\GCM;

/**
 * Implements GHASH function.
 *
 * This algorithm is specified in NIST SP-300-38D section 6.4.
 *
 * @see http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
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
     * @var string
     */
    protected $_subkey;

    /**
     * Constructor.
     *
     * @param string $subkey Hash subkey
     */
    public function __construct(string $subkey)
    {
        if (16 !== strlen($subkey)) {
            throw new \LengthException('Subkey must be 128 bits.');
        }
        $this->_subkey = $subkey;
    }

    /**
     * Functor method for `compute`.
     *
     * @param string $arg
     *
     * @return string
     */
    public function __invoke(string $arg): string
    {
        return $this->compute($arg);
    }

    /**
     * Compute hash.
     *
     * @param string $X Input string
     *
     * @return string Hash
     */
    public function compute(string $X): string
    {
        $len = strlen($X);
        if (0 !== $len % 16) {
            throw new \UnexpectedValueException(
                'Input string must be a multiple of 128 bits.');
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
     * Apply block multiplication operation.
     *
     * See NIST SP-800-38D, chapter 6.3 for the details.
     *
     * @param string $X
     * @param string $Y
     *
     * @return string
     */
    private function _mult(string $X, string $Y): string
    {
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

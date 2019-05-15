<?php

declare(strict_types = 1);

namespace Sop\GCM;

use Sop\GCM\Cipher\Cipher;
use Sop\GCM\Exception\AuthenticationException;

/**
 * Implements encryption and decryption in Galois/Counter Mode.
 *
 * @see http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 * @see http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
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
     * Array of supported t-values, that is, the bit length of the
     * authentication tag.
     *
     * See NIST SP-800-38D section 5.2.1.2 for the details.
     *
     * @internal
     *
     * @var array
     */
    const SUPPORTED_T_LEN = [128, 120, 112, 104, 96, 64, 32];

    /**
     * Cipher.
     *
     * @var Cipher
     */
    protected $_cipher;

    /**
     * Authentication tag length in bytes.
     *
     * @var int
     */
    protected $_tagLength;

    /**
     * Constructor.
     *
     * @param Cipher $cipher     Cipher implementation
     * @param int    $tag_length Authentication tag length in bytes
     *
     * @throws \DomainException If tag length is not supported
     */
    public function __construct(Cipher $cipher, int $tag_length = 16)
    {
        if (!in_array($tag_length << 3, self::SUPPORTED_T_LEN)) {
            throw new \DomainException(
                "Tag length {$tag_length} is not supported.");
        }
        $this->_cipher = $cipher;
        $this->_tagLength = $tag_length;
    }

    /**
     * Encrypt plaintext.
     *
     * @param string $P  Plaintext
     * @param string $A  Additional authenticated data
     * @param string $K  Encryption key
     * @param string $IV Initialization vector
     *
     * @throws \RuntimeException For generic errors
     *
     * @return array Tuple of ciphertext `C` and authentication tag `T`
     */
    public function encrypt(string $P, string $A, string $K, string $IV): array
    {
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
     * @param string $C  Ciphertext
     * @param string $T  Authentication tag
     * @param string $A  Additional authenticated data
     * @param string $K  Encryption key
     * @param string $IV Initialization vector
     *
     * @throws AuthenticationException If message authentication fails
     * @throws \RuntimeException       For generic errors
     *
     * @return string Plaintext `P`
     */
    public function decrypt(string $C, string $T, string $A, string $K, string $IV): string
    {
        $ghash = new GHASH($this->_cipher->encrypt(self::ZB_128, $K));
        // generate pre-counter block
        $J0 = $this->_generateJ0($IV, $ghash);
        // generate authentication tag
        $T2 = $this->_computeAuthTag($A, $C, $J0, $K, $ghash);
        // check that authentication tag matches
        if (!hash_equals($T2, $T)) {
            throw new AuthenticationException('Authentication failed.');
        }
        // decrypt
        return $this->_gctr(self::_inc32($J0), $C, $K);
    }

    /**
     * Convert string to GMP number.
     *
     * String is interpreted as an unsigned integer with big endian order and
     * the most significant byte first.
     *
     * @param string $data Binary data
     *
     * @return \GMP
     */
    public static function strToGMP(string $data): \GMP
    {
        $num = gmp_import($data, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        assert($num instanceof \GMP, new \RuntimeException('gmp_import() failed.'));
        return $num;
    }

    /**
     * Convert GMP number to string.
     *
     * Returned string represents an unsigned integer with big endian order and
     * the most significant byte first.
     *
     * @param \GMP $num  GMP number
     * @param int  $size Width of the string in bytes
     *
     * @return string Binary data
     */
    public static function gmpToStr(\GMP $num, int $size): string
    {
        $data = gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        $len = strlen($data);
        if ($len < $size) {
            $data = str_repeat("\0", $size - $len) . $data;
        }
        return $data;
    }

    /**
     * Generate pre-counter block.
     *
     * See NIST SP-300-38D section 7.1 step 2 for the details.
     *
     * @param string $IV    Initialization vector
     * @param GHASH  $ghash GHASH functor
     *
     * @return string
     */
    private function _generateJ0(string $IV, GHASH $ghash): string
    {
        // if len(IV) = 96
        if (12 === strlen($IV)) {
            return $IV . "\0\0\0\1";
        }
        $data = self::_pad128($IV) . self::ZB_64 . self::_uint64(strlen($IV) << 3);
        return $ghash($data);
    }

    /**
     * Apply GCTR algorithm.
     *
     * See NIST SP-300-38D section 6.5 for the details.
     *
     * @param string $ICB Initial counter block
     * @param string $X   Input data
     * @param string $K   Encryption key
     *
     * @return string Output data
     */
    private function _gctr(string $ICB, string $X, string $K): string
    {
        // if data is an empty string, return an empty string
        if ('' === $X) {
            return '';
        }
        // number of blocks
        $n = ceil(strlen($X) / 16);
        $CB = $ICB;
        $Y = '';
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
     * Compute authentication tag.
     *
     * See NIST SP-300-38D section 7.1 steps 5-6 for the details.
     *
     * @param string $A     Additional authenticated data
     * @param string $C     Ciphertext
     * @param string $J0    Pre-counter block
     * @param string $K     Encryption key
     * @param GHASH  $ghash GHASH functor
     *
     * @return string Authentication tag `T`
     */
    private function _computeAuthTag(string $A, string $C, string $J0, string $K,
        GHASH $ghash): string
    {
        $data = self::_pad128($A) . self::_pad128($C) .
             self::_uint64(strlen($A) << 3) . self::_uint64(strlen($C) << 3);
        $S = $ghash($data);
        return substr($this->_gctr($J0, $S, $K), 0, $this->_tagLength);
    }

    /**
     * Pad data to 128 bit block boundary.
     *
     * @param string $data
     *
     * @return string
     */
    private static function _pad128(string $data): string
    {
        $padlen = 16 - strlen($data) % 16;
        if (16 !== $padlen) {
            $data .= str_repeat("\0", $padlen);
        }
        return $data;
    }

    /**
     * Increment 32 rightmost bits of the counter block.
     *
     * See NIST SP-300-38D section 6.2 for the details.
     *
     * @param string $X
     *
     * @return string
     */
    private static function _inc32(string $X): string
    {
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
     *
     * @return string
     */
    private static function _uint64(int $num): string
    {
        // truncate on 32 bit hosts
        if (PHP_INT_SIZE < 8) {
            return "\0\0\0\0" . pack('N', $num);
        }
        return pack('J', $num);
    }
}

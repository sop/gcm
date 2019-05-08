<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\GCM\GHASH;

/**
 * @group gcm
 * @group ghash
 *
 * @internal
 */
class GHASHTest extends TestCase
{
    const SUBKEY = '0123456789abcdef';

    const B = '0123456789abcdef';

    public function testCreate()
    {
        $ghash = new GHASH(self::SUBKEY);
        $this->assertInstanceOf(GHASH::class, $ghash);
        return $ghash;
    }

    public function testCreateFail()
    {
        $this->expectException(\LengthException::class);
        new GHASH('fail');
    }

    /**
     * @depends testCreate
     *
     * @param GHASH $ghash
     */
    public function testComputeOneBlock(GHASH $ghash)
    {
        $hash = $ghash->compute(self::B);
        $this->assertIsString($hash);
    }

    /**
     * @depends testCreate
     *
     * @param GHASH $ghash
     */
    public function testComputeMultiBlock(GHASH $ghash)
    {
        $hash = $ghash->compute(self::B . self::B . self::B);
        $this->assertIsString($hash);
    }

    /**
     * @depends testCreate
     *
     * @param GHASH $ghash
     */
    public function testInvalidLength(GHASH $ghash)
    {
        $this->expectException(\UnexpectedValueException::class);
        $ghash->compute('fails');
    }

    /**
     * @depends testCreate
     *
     * @param GHASH $ghash
     */
    public function testInvoke(GHASH $ghash)
    {
        $this->assertIsString($ghash(self::B));
    }
}

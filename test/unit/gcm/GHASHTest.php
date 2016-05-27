<?php

use GCM\GHASH;


class GHASHTest extends PHPUnit_Framework_TestCase
{
	const SUBKEY = "0123456789abcdef";
	
	const B = "0123456789abcdef";
	
	public function testCreate() {
		$ghash = new GHASH(self::SUBKEY);
		$this->assertInstanceOf(GHASH::class, $ghash);
		return $ghash;
	}
	
	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testCreateFail() {
		new GHASH("fail");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GHASH $ghash
	 */
	public function testComputeOneBlock(GHASH $ghash) {
		$hash = $ghash->compute(self::B);
		$this->assertInternalType("string", $hash);
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GHASH $ghash
	 */
	public function testComputeMultiBlock(GHASH $ghash) {
		$hash = $ghash->compute(self::B . self::B . self::B);
		$this->assertInternalType("string", $hash);
	}
	
	/**
	 * @depends testCreate
	 * @expectedException UnexpectedValueException
	 *
	 * @param GHASH $ghash
	 */
	public function testInvalidLength(GHASH $ghash) {
		$ghash->compute("fails");
	}
	
	/**
	 * @depends testCreate
	 *
	 * @param GHASH $ghash
	 */
	public function testInvoke(GHASH $ghash) {
		$this->assertInternalType("string", $ghash(self::B));
	}
}

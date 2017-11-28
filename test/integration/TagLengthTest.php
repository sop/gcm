<?php

use GCM\GCM;
use GCM\Cipher\AES\AES128Cipher;
use PHPUnit\Framework\TestCase;

class TagLengthTest extends TestCase
{
    const PLAINTEXT = "My hovercraft is full of eels.";
    
    const AAD = "Ahh, matches!";
    
    const KEY = "0123456789abcdef";
    
    const IV = "fedcba987654";
    
    /**
     * @dataProvider provideTagLength
     */
    public function testTagLength($tag_length)
    {
        $gcm = new GCM(new AES128Cipher(), $tag_length);
        list($C, $T) = $gcm->encrypt(self::PLAINTEXT, self::AAD, self::KEY,
            self::IV);
        $this->assertEquals($tag_length, strlen($T));
        $plaintext = $gcm->decrypt($C, $T, self::AAD, self::KEY, self::IV);
        $this->assertEquals(self::PLAINTEXT, $plaintext);
    }
    
    public function provideTagLength()
    {
        return array(
            /* @formatter:off */
            [16],
            [15],
            [14],
            [13],
            [12],
            [8],
            [4]
            /* @formatter:on */
        );
    }
}

<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\GCM\AESGCM;

/**
 * @group gcm
 * @group aes
 *
 * @internal
 */
class AESGCMTest extends TestCase
{
    const PLAINTEXT = 'PAYLOAD';

    const AAD = 'OTHER DATA';

    const KEY = '0123456789abcdef';

    const IV = 'fedcba987654';

    public function testEncrypt()
    {
        [$ciphertext, $auth_tag] = AESGCM::encrypt(self::PLAINTEXT,
            self::AAD, self::KEY, self::IV);
        $this->assertEquals(strlen(self::PLAINTEXT), strlen($ciphertext));
        $this->assertEquals(16, strlen($auth_tag));
        return [$ciphertext, $auth_tag];
    }

    /**
     * @depends testEncrypt
     *
     * @param array $data
     */
    public function testDecrypt($data)
    {
        $plaintext = AESGCM::decrypt($data[0], $data[1], self::AAD, self::KEY,
            self::IV);
        $this->assertEquals(self::PLAINTEXT, $plaintext);
    }
}

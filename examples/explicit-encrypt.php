<?php
/**
 * Encrypt a message without additional authenticated data using AES-192
 * as an underlying cipher and produce a 104-bit (13 bytes) authentication tag.
 *
 * php explicit-encrypt.php
 */

declare(strict_types = 1);

use Sop\GCM\Cipher\AES\AES192Cipher;
use Sop\GCM\GCM;

require dirname(__DIR__) . '/vendor/autoload.php';

$plaintext = 'Secret message.';
// 192-bit encryption key
$key = '012345678901234567890123';
// random 128-bit initialization vector
$iv = openssl_random_pseudo_bytes(16);
// configure GCM object with AES-192 cipher and 13-bytes long authentication tag
$gcm = new GCM(new AES192Cipher(), 13);
// encrypt and generate authentication tag
[$ciphertext, $auth_tag] = $gcm->encrypt($plaintext, '', $key, $iv);
// print the ciphertext along with the authentication tag
// and the initialization vector
echo bin2hex($ciphertext) . "\n" . bin2hex($auth_tag) . "\n" . bin2hex($iv) . "\n";

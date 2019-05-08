<?php
/**
 * Encrypt a message with additional authenticated data, using a 128-bit key.
 *
 * php encrypt.php
 */

declare(strict_types = 1);

use Sop\GCM\AESGCM;

require dirname(__DIR__) . '/vendor/autoload.php';

// data to encrypt
$plaintext = 'Meet me at the pier at midnight.';
// additional authenticated data
// this is only integrity protected but not encrypted
$aad = 'Additional info';
// encryption key
$key = 'some 128 bit key';
// random initialization vector
$iv = openssl_random_pseudo_bytes(12);
// encrypt and generate the authentication tag
[$ciphertext, $auth_tag] = AESGCM::encrypt($plaintext, $aad, $key, $iv);
// print the ciphertext along with the authentication tag
// and the initialization vector
echo bin2hex($ciphertext) . "\n" . bin2hex($auth_tag) . "\n" . bin2hex($iv) . "\n";

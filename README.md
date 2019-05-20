# GCM

[![Build Status](https://travis-ci.org/sop/gcm.svg?branch=master)](https://travis-ci.org/sop/gcm)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/sop/gcm/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/sop/gcm/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/sop/gcm/badge.svg?branch=master)](https://coveralls.io/github/sop/gcm?branch=master)
[![License](https://poser.pugx.org/sop/gcm/license)](https://github.com/sop/gcm/blob/master/LICENSE)

A PHP library for Galois/Counter Mode
([GCM](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf))
encryption.

Supports AES-GCM with 128, 192 and 256-bit key sizes and specified
authentication tag lengths.

## Requirements

- PHP >=7.2
- openssl
- hash
- gmp

## Installation

This library is available on
[Packagist](https://packagist.org/packages/sop/gcm).

    composer require sop/gcm

## Code examples

Here are some simple usage examples. Namespaces are omitted for brevity.

### Encrypt

Encrypt a message with additional authenticated data, using a 128-bit key.

```php
[$ciphertext, $auth_tag] = AESGCM::encrypt(
    'Meet me at the pier at midnight.',
    'Additional info', 'some 128 bit key', 'random iv-string');
echo bin2hex($ciphertext) . "\n" . bin2hex($auth_tag);
```

Outputs:

    5a24cfccf2e6c7763f71cd2ef6bcaa78385b16328593a93a43146d587e314ed8
    389cc23f815d453686915530937d2053

See [`/examples`](https://github.com/sop/gcm/blob/master/examples/encrypt.php) for a detailed version.

### Decrypt

Decrypt a ciphertext created above. Additional authenticated data must
be the same, otherwise authentication fails and an exception shall be thrown.

```php
$plaintext = AESGCM::decrypt($ciphertext, $auth_tag,
    'Additional info', 'some 128 bit key', 'random iv-string');
echo $plaintext;
```

Outputs:

    Meet me at the pier at midnight.

See [`/examples`](https://github.com/sop/gcm/blob/master/examples/decrypt.php) for a detailed version.

### Using explicit cipher method and tag length

[Encrypt](https://github.com/sop/gcm/blob/master/examples/explicit-encrypt.php)
a message without additional authenticated data using AES-192
as an underlying cipher and produce a 104-bit (13 bytes) authentication tag.

```php
$key = '012345678901234567890123'; // 192-bit encryption key
$iv = hex2bin('beadfacebadc0fee'); // random initialization vector
$gcm = new GCM(new AES192Cipher(), 13);
[$ciphertext, $auth_tag] = $gcm->encrypt('Secret message.', '', $key, $iv);
echo bin2hex($ciphertext) . "\n" . bin2hex($auth_tag);
```

Outputs:

    7bcd4e423016213c60a3c0a3e3fc0c
    027b14cfea0a2307649fc67b1d

[Decrypting](https://github.com/sop/gcm/blob/master/examples/explicit-decrypt.php)
the output from above.

```php
$plaintext = $gcm->decrypt($ciphertext, $auth_tag, '', $key, $iv);
echo $plaintext;
```

Outputs:

    Secret message.

## References

- [GCM Specification](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf)
- [NIST Special Publication 800-38D](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf)

## License

This project is licensed under the MIT License.

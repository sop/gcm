[![Build Status](https://travis-ci.org/sop/gcm.svg?branch=master)](https://travis-ci.org/sop/gcm)
[![Coverage Status](https://coveralls.io/repos/github/sop/gcm/badge.svg?branch=master)](https://coveralls.io/github/sop/gcm?branch=master)
[![License](https://poser.pugx.org/sop/gcm/license)](https://packagist.org/packages/sop/gcm)

# GCM
A PHP library for Galois/Counter Mode
([GCM](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf))
encryption.

Supports AES-GCM with 128, 192 and 256-bit key sizes.

## Installation
This library is available on
[Packagist](https://packagist.org/packages/sop/gcm).

    composer require sop/gcm

## Code examples
Here are some simple usage examples. Namespaces are omitted for brevity.

### Encrypt
Encrypt a message with additional authenticated data, using a 128-bit key.
```php
list($ciphertext, $auth_tag) = AESGCM::encrypt(
	"Meet me at the pier at midnight.",
	"Additional info", "some 128 bit key", "random string");
echo bin2hex($ciphertext) . "\n" . bin2hex($auth_tag);
```
Outputs:

    e0ce4d816a3f341f0062c6dc99b83692ad265fc4b34df2a3b593dfdb2ecdaed3
    9e2ffd7fa0df4d275ad0300416e23bdd

### Decrypt
Decrypt a ciphertext created above. Additional authenticated data must
be the same, otherwise authentication fails and exception shall be thrown.
```php
$plaintext = AESGCM::decrypt($ciphertext, $auth_tag,
	"Additional info", "some 128 bit key", "random string");
echo $plaintext;
```
Outputs:

    Meet me at the pier at midnight.

## License
This project is licensed under the MIT License.

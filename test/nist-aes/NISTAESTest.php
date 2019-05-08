<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\GCM\AESGCM;

/**
 * Perform test vectors from GCM specification appendix B.
 *
 * @see http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 *
 * @internal
 */
class NISTAESTestVectorsTest extends TestCase
{
    /**
     * @dataProvider provideCases
     *
     * @param mixed $K
     * @param mixed $P
     * @param mixed $A
     * @param mixed $IV
     * @param mixed $C
     * @param mixed $T
     */
    public function testCase($K, $P, $A, $IV, $C, $T)
    {
        [$ciphertext, $auth_tag] = AESGCM::encrypt($P, $A, $K, $IV);
        $this->assertEquals($C, $ciphertext);
        $this->assertEquals($T, $auth_tag);
        $plaintext = AESGCM::decrypt($ciphertext, $auth_tag, $A, $K, $IV);
        $this->assertEquals($P, $plaintext);
    }

    public function provideCases()
    {
        $cases = [
            [
                // Test Case 1
                '00000000000000000000000000000000', // key
                '', // plaintext
                '', // additional authenticated data
                '000000000000000000000000', // initialization vector
                '', // ciphertext
                '58e2fccefa7e3061367f1d57a4e7455a', // authentication tag
            ],
            [
                // Test Case 2
                '00000000000000000000000000000000', // K
                '00000000000000000000000000000000', // P
                '', // A
                '000000000000000000000000', // IV
                '0388dace60b6a392f328c2b971b2fe78', // C
                'ab6e47d42cec13bdf53a67b21257bddf', // T
            ],
            [
                // Test Case 3
                'feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b391aafd255', // P
                '', // A
                'cafebabefacedbaddecaf888', // IV
                '42831ec2217774244b7221b784d0d49c
e3aa212f2c02a4e035c17e2329aca12e
21d514b25466931c7d8f6a5aac84aa05
1ba30b396a0aac973d58e091473f5985', // C
                '4d5c2af327cd64a62cf35abd2ba6fab4', // T
            ],
            [
                // Test Case 4
                'feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                'cafebabefacedbaddecaf888', // IV
                '42831ec2217774244b7221b784d0d49c
e3aa212f2c02a4e035c17e2329aca12e
21d514b25466931c7d8f6a5aac84aa05
1ba30b396a0aac973d58e091', // C
                '5bc94fbc3221a5db94fae95ae7121a47', // T
            ],
            [
                // Test Case 5
                'feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                'cafebabefacedbad', // IV
                '61353b4c2806934a777ff51fa22a4755
699b2a714fcdc6f83766e5f97b6c7423
73806900e49f24b22b097544d4896b42
4989b5e1ebac0f07c23f4598', // C
                '3612d2e79e3b0785561be14aaca2fccb', // T
            ],
            [
                // Test Case 6
                'feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                '9313225df88406e555909c5aff5269aa
6a7a9538534f7da1e4c303d2a318a728
c3c0c95156809539fcf0e2429a6b5254
16aedbf5a0de6a57a637b39b', // IV
                '8ce24998625615b603a033aca13fb894
be9112a5c3a211a8ba262a3cca7e2ca7
01e4a9a4fba43c90ccdcb281d48c7c6f
d62875d2aca417034c34aee5', // C
                '619cc5aefffe0bfa462af43c1699d050', // T
            ],
            [
                // Test Case 7
                '00000000000000000000000000000000
0000000000000000', // K
                '', // P
                '', // A
                '000000000000000000000000', // IV
                '', // C
                'cd33b28ac773f74ba00ed1f312572435', // T
            ],
            [
                // Test Case 8
                '00000000000000000000000000000000
0000000000000000', // K
                '00000000000000000000000000000000', // P
                '', // A
                '000000000000000000000000', // IV
                '98e7247c07f0fe411c267e4384b0f600', // C
                '2ff58d80033927ab8ef4d4587514f0fb', // T
            ],
            [
                // Test Case 9
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b391aafd255', // P
                '', // A
                'cafebabefacedbaddecaf888', // IV
                '3980ca0b3c00e841eb06fac4872a2757
859e1ceaa6efd984628593b40ca1e19c
7d773d00c144c525ac619d18c84a3f47
18e2448b2fe324d9ccda2710acade256', // C
                '9924a7c8587336bfb118024db8674a14', // T
            ],
            [
                // Test Case 10
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                'cafebabefacedbaddecaf888', // IV
                '3980ca0b3c00e841eb06fac4872a2757
859e1ceaa6efd984628593b40ca1e19c
7d773d00c144c525ac619d18c84a3f47
18e2448b2fe324d9ccda2710', // C
                '2519498e80f1478f37ba55bd6d27618c', // T
            ],
            [
                // Test Case 11
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                'cafebabefacedbad', // IV
                '0f10f599ae14a154ed24b36e25324db8
c566632ef2bbb34f8347280fc4507057
fddc29df9a471f75c66541d4d4dad1c9
e93a19a58e8b473fa0f062f7', // C
                '65dcc57fcf623a24094fcca40d3533f8', // T
            ],
            [
                // Test Case 12
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                '9313225df88406e555909c5aff5269aa
6a7a9538534f7da1e4c303d2a318a728
c3c0c95156809539fcf0e2429a6b5254
16aedbf5a0de6a57a637b39b', // IV
                'd27e88681ce3243c4830165a8fdcf9ff
1de9a1d8e6b447ef6ef7b79828666e45
81e79012af34ddd9e2f037589b292db3
e67c036745fa22e7e9b7373b', // C
                'dcf566ff291c25bbb8568fc3d376a6d9', // T
            ],
            [
                // Test Case 13
                '00000000000000000000000000000000
00000000000000000000000000000000', // K
                '', // P
                '', // A
                '000000000000000000000000', // IV
                '', // C
                '530f8afbc74536b9a963b4f1c4cb738b', // T
            ],
            [
                // Test Case 14
                '00000000000000000000000000000000
00000000000000000000000000000000', // K
                '00000000000000000000000000000000', // P
                '', // A
                '000000000000000000000000', // IV
                'cea7403d4d606b6e074ec5d3baf39d18', // C
                'd0d1c8a799996bf0265b98b5d48ab919', // T
            ],
            [
                // Test Case 15
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b391aafd255', // P
                '', // A
                'cafebabefacedbaddecaf888', // IV
                '522dc1f099567d07f47f37a32a84427d
643a8cdcbfe5c0c97598a2bd2555d1aa
8cb08e48590dbb3da7b08b1056828838
c5f61e6393ba7a0abcc9f662898015ad', // C
                'b094dac5d93471bdec1a502270e3cc6c', // T
            ],
            [
                // Test Case 16
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                'cafebabefacedbaddecaf888', // IV
                '522dc1f099567d07f47f37a32a84427d
643a8cdcbfe5c0c97598a2bd2555d1aa
8cb08e48590dbb3da7b08b1056828838
c5f61e6393ba7a0abcc9f662', // C
                '76fc6ece0f4e1768cddf8853bb2d551b', // T
            ],
            [
                // Test Case 17
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                'cafebabefacedbad', // IV
                'c3762df1ca787d32ae47c13bf19844cb
af1ae14d0b976afac52ff7d79bba9de0
feb582d33934a4f0954cc2363bc73f78
62ac430e64abe499f47c9b1f', // C
                '3a337dbf46a792c45e454913fe2ea8f2', // T
            ],
            [
                // Test Case 18
                'feffe9928665731c6d6a8f9467308308
feffe9928665731c6d6a8f9467308308', // K
                'd9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39', // P
                'feedfacedeadbeeffeedfacedeadbeef
abaddad2', // A
                '9313225df88406e555909c5aff5269aa
6a7a9538534f7da1e4c303d2a318a728
c3c0c95156809539fcf0e2429a6b5254
16aedbf5a0de6a57a637b39b', // IV
                '5a8def2f0c9e53f1f75d7853659e2a20
eeb2b22aafde6419a058ab4f6f746bf4
0fc0c3b780f244452da3ebf1c5d82cde
a2418997200ef82e44ae7e3f', // C
                'a44a8266ee1c8eb0c8b5d4cf5ae9f19a', // T
            ],
        ];
        return array_map(
            function ($data) {
                return array_map(
                    function ($hexstr) {
                        return hex2bin(
                            preg_replace('/[^0-9a-f]/i', '', $hexstr));
                    }, $data);
            }, $cases);
    }
}

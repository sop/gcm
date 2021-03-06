<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\GCM\AESGCM;
use Sop\GCM\Cipher\AES\AESCipher;
use Sop\GCM\GCM;

/**
 * Perform test vectors from "MACsec GCM - AES Test Vectors" document.
 *
 * @see http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
 *
 * @internal
 */
class MACSecAESTestVectorsTest extends TestCase
{
    /**
     * @dataProvider provideCases
     *
     * @param mixed $K  Key
     * @param mixed $P  Plaintext
     * @param mixed $A  Additional authenticated data
     * @param mixed $IV Initialization vector
     * @param mixed $C  Expected cipher text
     * @param mixed $T  Expected authentication tag
     */
    public function testCaseImpl($K, $P, $A, $IV, $C, $T)
    {
        $cipher = AESCipher::fromKeyLength(strlen($K));
        $gcm = new GCM($cipher);
        [$ciphertext, $auth_tag] = $gcm->encrypt($P, $A, $K, $IV);
        $this->assertEquals($C, $ciphertext);
        $this->assertEquals($T, $auth_tag);
        $plaintext = $gcm->decrypt($ciphertext, $auth_tag, $A, $K, $IV);
        $this->assertEquals($P, $plaintext);
    }

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
    public function testCaseNative($K, $P, $A, $IV, $C, $T)
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
                // Test Case 2.1.1
                'AD7A2BD03EAC835A6F620FDCB506B345', // key
                '', // plaintext
                'D609B1F056637A0D46DF998D88E5222A
B2C2846512153524C0895E8108000F10
1112131415161718191A1B1C1D1E1F20
2122232425262728292A2B2C2D2E2F30
313233340001', // additional authenticated data
                '12153524C0895E81B2C28465', // initialization vector
                '', // ciphertext
                'F09478A9B09007D06F46E9B6A1DA25DD', // authentication tag
            ],
            [
                // Test Case 2.1.2
                'E3C08A8F06C6E3AD95A70557B23F7548
3CE33021A9C72B7025666204C69C0B72', // K
                '', // P
                'D609B1F056637A0D46DF998D88E5222A
B2C2846512153524C0895E8108000F10
1112131415161718191A1B1C1D1E1F20
2122232425262728292A2B2C2D2E2F30
313233340001', // A
                '12153524C0895E81B2C28465', // IV
                '', // C
                '2F0BC5AF409E06D609EA8B7D0FA5EA50', // T
            ],
            [
                // Test Case 2.2.1
                'AD7A2BD03EAC835A6F620FDCB506B345', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F303132333435363738393A0002', // P
                'D609B1F056637A0D46DF998D88E52E00
B2C2846512153524C0895E81', // A
                '12153524C0895E81B2C28465', // IV
                '701AFA1CC039C0D765128A665DAB6924
3899BF7318CCDC81C9931DA17FBE8EDD
7D17CB8B4C26FC81E3284F2B7FBA713D', // C
                '4F8D55E7D3F06FD5A13C0C29B9D5B880', // T
            ],
            [
                // Test Case 2.2.1
                'E3C08A8F06C6E3AD95A70557B23F7548
3CE33021A9C72B7025666204C69C0B72', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F303132333435363738393A0002', // P
                'D609B1F056637A0D46DF998D88E52E00
B2C2846512153524C0895E81', // A
                '12153524C0895E81B2C28465', // IV
                'E2006EB42F5277022D9B19925BC419D7
A592666C925FE2EF718EB4E308EFEAA7
C5273B394118860A5BE2A97F56AB7836', // C
                '5CA597CDBB3EDB8D1A1151EA0AF7B436', // T
            ],
            [
                // Test Case 2.3.1
                '071B113B0CA743FECCCF3D051F737382', // K
                '', // P
                'E20106D7CD0DF0761E8DCD3D88E54000
76D457ED08000F101112131415161718
191A1B1C1D1E1F202122232425262728
292A2B2C2D2E2F303132333435363738
393A0003', // A
                'F0761E8DCD3D000176D457ED', // IV
                '', // C
                '0C017BC73B227DFCC9BAFA1C41ACC353', // T
            ],
            [
                // Test Case 2.3.2
                '691D3EE909D7F54167FD1CA0B5D76908
1F2BDE1AEE655FDBAB80BD5295AE6BE7', // K
                '', // P
                'E20106D7CD0DF0761E8DCD3D88E54000
76D457ED08000F101112131415161718
191A1B1C1D1E1F202122232425262728
292A2B2C2D2E2F303132333435363738
393A0003', // A
                'F0761E8DCD3D000176D457ED', // IV
                '', // C
                '35217C774BBC31B63166BCF9D4ABED07', // T
            ],
            [
                // Test Case 2.4.1
                '071B113B0CA743FECCCF3D051F737382', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F30313233340004', // P
                'E20106D7CD0DF0761E8DCD3D88E54C2A
76D457ED', // A
                'F0761E8DCD3D000176D457ED', // IV
                '13B4C72B389DC5018E72A171DD85A5D3
752274D3A019FBCAED09A425CD9B2E1C
9B72EEE7C9DE7D52B3F3', // C
                'D6A5284F4A6D3FE22A5D6C2B960494C3', // T
            ],
            [
                // Test Case 2.4.2
                '691D3EE909D7F54167FD1CA0B5D76908
1F2BDE1AEE655FDBAB80BD5295AE6BE7', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F30313233340004', // P
                'E20106D7CD0DF0761E8DCD3D88E54C2A
76D457ED', // A
                'F0761E8DCD3D000176D457ED', // IV
                'C1623F55730C93533097ADDAD2566496
6125352B43ADACBD61C5EF3AC90B5BEE
929CE4630EA79F6CE519', // C
                '12AF39C2D1FDC2051F8B7B3C9D397EF2', // T
            ],
            [
                // Test Case 2.5.1
                '013FE00B5F11BE7F866D0CBBC55A7A90', // K
                '', // P
                '84C5D513D2AAF6E5BBD2727788E52300
8932D6127CFDE9F9E33724C608000F10
1112131415161718191A1B1C1D1E1F20
2122232425262728292A2B2C2D2E2F30
3132333435363738393A3B3C3D3E3F00
05', // A
                '7CFDE9F9E33724C68932D612', // IV
                '', // C
                '217867E50C2DAD74C28C3B50ABDF695A', // T
            ],
            [
                // Test Case 2.5.2
                '83C093B58DE7FFE1C0DA926AC43FB360
9AC1C80FEE1B624497EF942E2F79A823', // K
                '', // P
                '84C5D513D2AAF6E5BBD2727788E52300
8932D6127CFDE9F9E33724C608000F10
1112131415161718191A1B1C1D1E1F20
2122232425262728292A2B2C2D2E2F30
3132333435363738393A3B3C3D3E3F00
05', // A
                '7CFDE9F9E33724C68932D612', // IV
                '', // C
                '6EE160E8FAECA4B36C86B234920CA975', // T
            ],
            [
                // Test Case 2.6.1
                '013FE00B5F11BE7F866D0CBBC55A7A90', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F303132333435363738393A3B00
06', // P
                '84C5D513D2AAF6E5BBD2727788E52F00
8932D6127CFDE9F9E33724C6', // A
                '7CFDE9F9E33724C68932D612', // IV
                '3A4DE6FA32191014DBB303D92EE3A9E8
A1B599C14D22FB080096E13811816A3C
9C9BCF7C1B9B96DA809204E29D0E2A76
42', // C
                'BFD310A4837C816CCFA5AC23AB003988', // T
            ],
            [
                // Test Case 2.6.2
                '83C093B58DE7FFE1C0DA926AC43FB360
9AC1C80FEE1B624497EF942E2F79A823', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F303132333435363738393A3B00
06', // P
                '84C5D513D2AAF6E5BBD2727788E52F00
8932D6127CFDE9F9E33724C6', // A
                '7CFDE9F9E33724C68932D612', // IV
                '110222FF8050CBECE66A813AD09A73ED
7A9A089C106B959389168ED6E8698EA9
02EB1277DBEC2E68E473155A15A7DAEE
D4', // C
                'A10F4E05139C23DF00B3AADC71F0596A', // T
            ],
            [
                // Test Case 2.7.1
                '88EE087FD95DA9FBF6725AA9D757B0CD', // K
                '', // P
                '68F2E77696CE7AE8E2CA4EC588E54100
2E58495C08000F101112131415161718
191A1B1C1D1E1F202122232425262728
292A2B2C2D2E2F303132333435363738
393A3B3C3D3E3F404142434445464748
494A4B4C4D0007', // A
                '7AE8E2CA4EC500012E58495C', // IV
                '', // C
                '07922B8EBCF10BB2297588CA4C614523', // T
            ],
            [
                // Test Case 2.7.2
                '4C973DBC7364621674F8B5B89E5C1551
1FCED9216490FB1C1A2CAA0FFE0407E5', // K
                '', // P
                '68F2E77696CE7AE8E2CA4EC588E54100
2E58495C08000F101112131415161718
191A1B1C1D1E1F202122232425262728
292A2B2C2D2E2F303132333435363738
393A3B3C3D3E3F404142434445464748
494A4B4C4D0007', // A
                '7AE8E2CA4EC500012E58495C', // IV
                '', // C
                '00BDA1B7E87608BCBF470F12157F4C07', // T
            ],
            [
                // Test Case 2.8.1
                '88EE087FD95DA9FBF6725AA9D757B0CD', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F303132333435363738393A3B3C
3D3E3F404142434445464748490008', // P
                '68F2E77696CE7AE8E2CA4EC588E54D00
2E58495C', // A
                '7AE8E2CA4EC500012E58495C', // IV
                'C31F53D99E5687F7365119B832D2AAE7
0741D593F1F9E2AB3455779B078EB8FE
ACDFEC1F8E3E5277F8180B43361F6512
ADB16D2E38548A2C719DBA7228D840', // C
                '88F8757ADB8AA788D8F65AD668BE70E7', // T
            ],
            [
                // Test Case 2.8.2
                '4C973DBC7364621674F8B5B89E5C1551
1FCED9216490FB1C1A2CAA0FFE0407E5', // K
                '08000F101112131415161718191A1B1C
1D1E1F202122232425262728292A2B2C
2D2E2F303132333435363738393A3B3C
3D3E3F404142434445464748490008', // P
                '68F2E77696CE7AE8E2CA4EC588E54D00
2E58495C', // A
                '7AE8E2CA4EC500012E58495C', // IV
                'BA8AE31BC506486D6873E4FCE460E7DC
57591FF00611F31C3834FE1C04AD80B6
6803AFCF5B27E6333FA67C99DA47C2F0
CED68D531BD741A943CFF7A6713BD0', // C
                '2611CD7DAA01D61C5C886DC1A8170107', // T
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

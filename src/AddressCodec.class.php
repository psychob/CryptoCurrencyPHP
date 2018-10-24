<?php

namespace PsychoB\CryptoCurrencyPHP;

use Exception;

/*
 * Crypto Currency Address Codec Library.
 *
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve.
 *
 * Author Daniel Morante
 * Some parts may contain work based on Jan Moritz Lindemann, Matyas Danter and Joey Hewitt
*/


class AddressCodec
{
    /**
     * Returns the Uncompressed DER encoded public key.
     *
     * @param array $point Public key coordinates
     *
     * @return string (hex)
     */
    public static function Hex(array $point)
    {
        $derPubKey = '04' . $point['x'] . $point['y'];

        return $derPubKey;
    }

    /**
     * Returns the public key coordinates as an array.
     *
     * @param string $derPubKey Compressed or uncompressed DER Encoded Pubkey
     *
     * @return array
     *
     * @throws Exception If type of key is unknown
     */
    public static function Point($derPubKey)
    {
        // Check key type
        if (substr($derPubKey, 0, 2) == '04' && strlen($derPubKey) == 130) {
            // Uncompressed der encoded public key
            $x = substr($derPubKey, 2, 64);
            $y = substr($derPubKey, 66, 64);

            return array('x' => $x, 'y' => $y);

        // This is actually a compressed DER Public Key, send it to the correct function
        } elseif ((substr($derPubKey, 0, 2) == '02' || substr($derPubKey, 0, 2) == '03') && strlen($derPubKey) == 66) {
            return self::Decompress($derPubKey);

        // Unknown key type
        } else {
            throw new Exception('Invalid derPubKey format : ' . $derPubKey);
        }
    }


    /**
     * Returns the public key coordinates as an array.
     *
     * @param string $compressedDerPubKey Compressed or uncompressed DER Encoded Pubkey
     *
     * @return array
     *
     * @throws Exception If type of key is unknown
     */
    public static function Decompress($compressedDerPubKey)
    {
        // Check key type
        if ((substr($compressedDerPubKey, 0, 2) == '02' ||
            substr($compressedDerPubKey, 0, 2) == '03')
            && strlen($compressedDerPubKey) == 66
        ) {
            // Compressed der encoded public key
            $x = substr($compressedDerPubKey, 2, 64);

            // secp256k1
            $secp256k1 = new SECp256k1();
            $a = $secp256k1->a;
            $b = $secp256k1->b;
            $p = $secp256k1->p;

            // This is where the magic happens
            $y = PointMathGMP::calculateYWithX($x, $a, $b, $p, substr($compressedDerPubKey, 0, 2));

            return array('x' => $x, 'y' => $y);

        // This is actually a uncompressed DER Public Key, send it to the correct function
        } elseif (substr($compressedDerPubKey, 0, 2) == '04' && strlen($compressedDerPubKey) == 130) {
            return self::Point($compressedDerPubKey);

        // Unknown key type
        } else {
            throw new Exception('Invalid compressedDerPubKey format : ' . $compressedDerPubKey);
        }
    }

    /**
     * Returns the compressed DER encoded public key.
     *
     * @param array $pubKey Uncompressed public key
     *
     * @return string (hex)
     */
    public static function Compress($pubKey)
    {
        // If $pubKey['y'] is even
        if (gmp_strval(gmp_mod(gmp_init($pubKey['y'], 16), gmp_init(2, 10))) == 0) {
            $compressedDerPubKey = '02' . $pubKey['x'];

        // If $pubKey['y'] is odd
        } else {
            $compressedDerPubKey = '03' . $pubKey['x'];
        }

        return $compressedDerPubKey;
    }

    /**
     * Returns the HASH160 version of the Publick Key.
     *
     * @param string $derPubKey DER Encoded Pubkey
     *
     * @return string (hash160)
     */
    public static function Hash($derPubKey)
    {
        $sha256 = hash('sha256', hex2bin($derPubKey));
        $ripem160 = hash('ripemd160', hex2bin($sha256));

        return $ripem160;
    }

    /**
     * Returns the Bitcoin address version of the Publick Key.
     *
     * @param string $hex HEX Encoded Pubkey
     *
     * @return string (base58)
     */
    public static function Encode($hex, $prefix = "00")
    {
        // The magical prefix
        $hex_with_prefix = $prefix . $hex;

        // Checksum
        $sha256 = hash('sha256', hex2bin($hex_with_prefix));
        $checksum = hash('sha256', hex2bin($sha256));

        // Encode
        $address = $hex_with_prefix . substr($checksum, 0, 8);
        $address = Base58::Encode($address);

        return $address;
    }

    /**
     * Returns the Publick Key of the Bitcoin address.
     *
     * @param string $hex Bitcoin address
     *
     * @return string (hex)
     */
    public static function Decode($address)
    {
        $hex_with_prefix_and_check = Base58::Decode($address);
        $prefix = substr($hex_with_prefix_and_check, 0, 2);
        $checksum = substr($hex_with_prefix_and_check, -8);
        $hex = substr($hex_with_prefix_and_check, 2, -8);

        return $hex;
    }

    /**
     * Returns the private key under the Wallet Import Format.
     *
     * @param string $private_key Private key
     * @param string $prefix      Prefix
     * @param bool   $compressed  Is compressed
     *
     * @return string (base58)
     */
    public static function WIF($private_key, $prefix = '80', $compressed = true)
    {
        if ($compressed) {
            $private_key = $private_key . '01';
        }

        return strrev(self::Encode($private_key, $prefix));
    }

    /**
     * Returns the private key from Wallet Import Format.
     *
     * @param string $wif         Wallet Import Format
     * @param bool   $compressed  Is compressed
     *
     * @return string (hex)
     */
    public static function DeWIF($wif, $compressed = true)
    {
        $base58 = strrev($wif);
        $hex = self::Decode($base58);

        if ($compressed) {
            $hex = substr($hex, 0, -2);
        }

        return $hex;
    }
}

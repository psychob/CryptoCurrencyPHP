<?php

namespace PsychoB\CryptoCurrencyPHP;

use Exception;

/*
 * Object orieted interface to Helpful Point Math Operations using the GMP library.
 *
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve.
 *
 * Author Daniel Morante
 * Some parts may contain work based on Jan Moritz Lindemann, Matyas Danter and Joey Hewitt
*/

class PointMathGMP
{

    /**
     * Computes the result of a point doubling and returns the resulting point as an array.
     *
     * @param array $pt
     * @param int   $a
     * @param int   $p
     *
     * @return array Resulting point
     *
     * @throws Exception If things are unsupported
     */
    public static function doublePoint(array $pt, $a, $p)
    {
        $gcd = gmp_strval(gmp_gcd(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p), $p));
        if ($gcd != '1') {
            // See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9
            throw new Exception('This library doesn\'t yet supports point at infinity.');
        }

        // SLOPE = (3 * ptX^2 + a )/( 2*ptY )
        // Equals (3 * ptX^2 + a ) * ( 2*ptY )^-1
        $slope = gmp_mod(
            gmp_mul(
                gmp_invert(
                    gmp_mod(
                        gmp_mul(
                            gmp_init(2, 10),
                            $pt['y']
                        ),
                        $p
                    ),
                    $p
                ),
                gmp_add(
                    gmp_mul(
                        gmp_init(3, 10),
                        gmp_pow($pt['x'], 2)
                    ),
                    $a
                )
            ),
            $p
        );

        // nPtX = slope^2 - 2 * ptX
        // Equals slope^2 - ptX - ptX
        $nPt = array();
        $nPt['x'] = gmp_mod(
            gmp_sub(
                gmp_sub(
                    gmp_pow($slope, 2),
                    $pt['x']
                ),
                $pt['x']
            ),
            $p
        );

        // nPtY = slope * (ptX - nPtx) - ptY
        $nPt['y'] = gmp_mod(
            gmp_sub(
                gmp_mul(
                    $slope,
                    gmp_sub(
                        $pt['x'],
                        $nPt['x']
                    )
                ),
                $pt['y']
            ),
            $p
        );

        return $nPt;
    }

    /**
     * Computes the result of a point addition and returns the resulting point as an array.
     *
     * @param array $pt
     * @param array $pt2
     * @param int   $a
     * @param int   $p
     *
     * @return array Resulting point
     *
     * @throws Exception If things are unsupported
     */
    public static function addPoints(array $pt1, array $pt2, $a, $p)
    {
        if (gmp_cmp($pt1['x'], $pt2['x']) == 0 && gmp_cmp($pt1['y'], $pt2['y']) == 0) { //if identical
            return self::doublePoint($pt1, $a, $p);
        }

        $gcd = gmp_strval(gmp_gcd(gmp_sub($pt1['x'], $pt2['x']), $p));
        if ($gcd != '1') {
            // See See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9
            throw new Exception('This library doesn\'t yet supports point at infinity.');
        }

        // SLOPE = (pt1Y - pt2Y)/( pt1X - pt2X )
        // Equals (pt1Y - pt2Y) * ( pt1X - pt2X )^-1
        $slope = gmp_mod(
            gmp_mul(
                gmp_sub(
                    $pt1['y'],
                    $pt2['y']
                ),
                gmp_invert(
                    gmp_sub(
                        $pt1['x'],
                        $pt2['x']
                    ),
                    $p
                )
            ),
            $p
        );

        // nPtX = slope^2 - ptX1 - ptX2
        $nPt = array();
        $nPt['x'] = gmp_mod(
            gmp_sub(
                gmp_sub(
                    gmp_pow($slope, 2),
                    $pt1['x']
                ),
                $pt2['x']
            ),
            $p
        );

        // nPtX = slope * (ptX1 - nPtX) - ptY1
        $nPt['y'] = gmp_mod(
            gmp_sub(
                gmp_mul(
                    $slope,
                    gmp_sub(
                        $pt1['x'],
                        $nPt['x']
                    )
                ),
                $pt1['y']
            ),
            $p
        );

        return $nPt;
    }

    /**
     * Computes the result of a point multiplication and returns the resulting point as an array.
     *
     * @param string          $k (hex)
     * @param array(GMP, GMP) $pG
     * @param int             $base
     *
     * @return array(GMP, GMP) Resulting point
     *
     * @throws Exception If the resulting point is not on the curve
     */
    public static function mulPoint($k, array $pG, $a, $b, $p, $base = null)
    {
        //in order to calculate k*G
        if ($base == 16 || $base == null || is_resource($base)) {
            $k = gmp_init($k, 16);
        }

        if ($base == 10) {
            $k = gmp_init($k, 10);
        }

        $kBin = gmp_strval($k, 2);

        $lastPoint = $pG;
        for ($i = 1; $i < strlen($kBin); $i++) {
            if (substr($kBin, $i, 1) == 1) {
                $dPt = self::doublePoint($lastPoint, $a, $p);
                $lastPoint = self::addPoints($dPt, $pG, $a, $p);
            } else {
                $lastPoint = self::doublePoint($lastPoint, $a, $p);
            }
        }

        if (!self::validatePoint(gmp_strval($lastPoint['x'], 16), gmp_strval($lastPoint['y'], 16), $a, $b, $p)
        ) {
            throw new Exception('The resulting point is not on the curve.');
        }

        return $lastPoint;
    }

    /**
     * Calculates the square root of $a mod p and returns the 2 solutions as an array.
     *
     * @param int $a
     * @param int $a
     *
     * @return array|null
     *
     * @throws Exception If something isn't supported
     */
    public static function sqrt($a, $p)
    {
        if (gmp_legendre($a, $p) != 1) {
            //no result
            return null;
        }

        if (gmp_strval(gmp_mod($p, gmp_init(4, 10)), 10) == 3) {
            $sqrt1 = gmp_powm(
                $a,
                gmp_div_q(
                    gmp_add($p, gmp_init(1, 10)),
                    gmp_init(4, 10)
                ),
                $p
            );
            // there are always 2 results for a square root
            // In an infinite number field you have -2^2 = 2^2 = 4
            // In a finite number field you have a^2 = (p-a)^2
            $sqrt2 = gmp_mod(gmp_sub($p, $sqrt1), $p);

            return array($sqrt1, $sqrt2);
        } else {
            throw new Exception('P % 4 != 3 , this isn\'t supported yet.');
        }
    }

    /**
     * Calculate the Y coordinates for a given X coordinate.
     *
     * @param int  $x
     * @param int  $a
     * @param int  $b
     * @param int  $p
     * @param null $derEvenOrOddCode
     *
     * @return array|null|string
     */
    public static function calculateYWithX($x, $a, $b, $p, $derEvenOrOddCode = null)
    {
        $x = gmp_init($x, 16);
        $y2 = gmp_mod(
            gmp_add(
                gmp_add(
                    gmp_powm($x, gmp_init(3, 10), $p),
                    gmp_mul($a, $x)
                ),
                $b
            ),
            $p
        );

        $y = self::sqrt($y2, $p);

        // If there is no result
        if (!$y) {
            return null;
        }

        if (!$derEvenOrOddCode) {
            return $y;
        } else {
            if ($derEvenOrOddCode == '02') { // Even
                $resY = null;
                if (false == gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10)) {
                    $resY = gmp_strval($y[0], 16);
                }
                if (false == gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10)) {
                    $resY = gmp_strval($y[1], 16);
                }
                if ($resY) {
                    while (strlen($resY) < 64) {
                        $resY = '0' . $resY;
                    }
                }
                return $resY;
            } else {
                if ($derEvenOrOddCode == '03') { // Odd
                    $resY = null;
                    if (true == gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10)) {
                        $resY = gmp_strval($y[0], 16);
                    }
                    if (true == gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10)) {
                        $resY = gmp_strval($y[1], 16);
                    }
                    if ($resY) {
                        while (strlen($resY) < 64) {
                            $resY = '0' . $resY;
                        }
                    }
                    return $resY;
                }
            }
        }

        return null;
    }

    /**
     * Returns true if the point is on the curve and false if it isn't.
     *
     * @param int $x
     * @param int $y
     * @param int $a
     * @param int $b
     * @param int $p
     *
     * @return bool
     */
    public static function validatePoint($x, $y, $a, $b, $p)
    {
        $x = gmp_init($x, 16);
        $y2 = gmp_mod(
            gmp_add(
                gmp_add(
                    gmp_powm($x, gmp_init(3, 10), $p),
                    gmp_mul($a, $x)
                ),
                $b
            ),
            $p
        );
        $y = gmp_mod(gmp_pow(gmp_init($y, 16), 2), $p);

        if (gmp_cmp($y2, $y) == 0) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns Negated Point (Y).
     *
     * @param array(GMP, GMP) $point
     *
     * @return array(GMP, GMP)
     */
    public static function negatePoint($point)
    {
        return array('x' => $point['x'], 'y' => gmp_neg($point['y']));
    }

    /**
     * Checks is the given number (DEC string) is even.
     *
     * @param string $number
     *
     * @return bool
     */
    public static function isEvenNumber($number)
    {
        return (((int)$number[strlen($number) - 1]) & 1) == 0;
    }

    /**
     * Converts BIN to GMP
     *
     * @param string $binStr
     *
     * @return int
     */
    public static function bin2gmp($binStr)
    {
        $v = gmp_init('0');

        for ($i = 0; $i < strlen($binStr); $i++) {
            $v = gmp_add(gmp_mul($v, 256), ord($binStr[$i]));
        }

        return $v;
    }
}

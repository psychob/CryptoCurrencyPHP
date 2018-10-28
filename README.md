# Crypto Currency for PHP

A collection of common utilities and libraries in PHP for use with Bitcoin and Zetacoin compatable crypto currencies ustilizing the secp256k1 ECDSA curve.  Full documentation and extended examples are avialable at: http://www.unibia.com/unibianet/developer/crypto-currency-php-libraries-pure-php-zetacoin-and-bitcoin-compatable-crypto-currencies

The code may be messy and all over the place, but I'm still pulling things together as I merge this code base with items from the PHPECC codebase.

The current features include:

- Private Key Generation and Loading
- Public Address Print Out
- Message Signing and Verification
- Address Generation and Validation
- Address compression, de-compression, encoding, and decoding.
- Supports Arbitrary Address Prefixes
 
Currently, the following items are working

- `Base58`
- `SECp256k1`
- `PointMathGMP`
- `AddressValidation`
- `AddressCodec`
- `PrivateKey`
- `Signature`
- `Wallet`

Planned features include:

- Transaction Generation
- Transaction Signing

# Installation

## Requirements 

The current implementation requires PHP 5.5 or later and the `php-gmp` extension.  Future version will automaticly detect and switch between GMP and BCMATH.

## With Composer

The reccomended way to install this library is using [Composer](https://getcomposer.org/).

You need to include package `psychob/crypto-currency` in your `composer.json`:

```bash
$ composer require psychob/crypto-currency
```

You also need to include autoloader in your code and use `PsychoB\CryptoCurrencyPHP` namespace:

```php
<?php

use PsychoB\CryptoCurrencyPHP\AddressCodec;
use PsychoB\CryptoCurrencyPHP\Wallet;

require 'vendor/autoload.php';
```

## Without Composer

You could also clone this repository and manually include all classes:

```php
<?php

require 'src/Base58.class.php';
require 'src/SECp256k1.class.php';
require 'src/PointMathGMP.class.php';
require 'src/AddressCodec.class.php';
require 'src/AddressCodec.class.php';
require 'src/PrivateKey.class.php';
require 'src/Wallet.class.php';
require 'src/Signature.class.php';

use PsychoB\CryptoCurrencyPHP\AddressCodec;
use PsychoB\CryptoCurrencyPHP\Wallet;
```

# Usage

## AddressCodec

The AddressCodec class provides a simple interface for common Zetacoin/Bitcoin (and compatable) address functions.

The most basic example, get the X and Y coordnates of a DER Encoded public key (old format):

```php
$derPublicKey = '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235';

$point = AddressCodec::Point($derPublicKey);

echo $point['x'];
echo $point['y'];
```

That will return an array with both X and Y:

```
X = a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd
Y = 5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235
```

The more usefull method is with the new compressed public keys used by modern crypto currencies:

```php
$compressedPublicKey = '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';

$point = AddressCodec::Decompress($compressedPublicKey);

echo $point['x'];
echo $point['y'];
```

Works the other way around too:

```php
$compressedPublicKey = AddressCodec::Compress($point);
$derPublicKey = AddressCodec::Hex($point);
```

On to the more usefull items, Encode a public key into a Crypto Currency address. First Hash your public key then Encode it:

```php
$hash = AddressCodec::Hash($compressedPublicKey);
$address = AddressCodec::Encode($hash);

echo $address;
```

Gives you:

```
Address = 1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV
```

Specify your own prefix (in HEX):

```php
$address = AddressCodec::Encode($hash, "50");
```

Gives you:

```
Address = ZS67wSwchNQFuTt3abnK4HjpjQ2x79YZed
```

## Wallet

The Wallet class provides a simple interface to common Zetacoin/Bitcoin (and compatable) functions.  At the moment, the wallet can load a private key, display it's associated receive address, and of course, message signing/verification!

First you must generate or specify a PrivateKey:

```php
$private = new PrivateKey('1234567890abcdefNOTAREALKEY23456789012345678789');
// Or
$private = new PrivateKey();
```

Load this PrivateKey into the Wallet. Optionally set the network prefix (aka address version/prefix) as a HEX, and network name:
```php
$wallet = new Wallet($private);

// Setting "Z" for "Zetacoin" Address version is 80 in decimal. '50' in HEX.
$wallet->setNetworkPrefix("50");
$wallet->setNetworkName("Zetacoin");
```

Print out your recieve address:

```php
echo $wallet->getAddress();
```

Sign a message:

```php
echo $message =  $wallet->signMessage("Test 1234");
```

Puts out something like:

```
-----BEGIN ZETACOIN SIGNED MESSAGE-----
Test 1234
-----BEGIN SIGNATURE-----
ZJFVhALJwWV1uz8m1YoXXyvNqFMu4h7A94
H7wVT/QJEd3xIonGorLsDxXHg8DE5byo9fcD5h/LHH02KX7nFKjyvH7AE7PjioCQid4qKOjuMh430G37gKIupDc=
-----END ZETACOIN SIGNED MESSAGE-----
```

Verify a signed message using the Satoshi client's standard message signature format. A PrivateKey is not required when you only need to verify signed messsages: 

```php
$message = PHP_EOL;
$message .= "-----BEGIN ZETACOIN SIGNED MESSAGE-----" . PHP_EOL;
$message .= "Test 1234" . PHP_EOL;
$message .= "-----BEGIN SIGNATURE-----" . PHP_EOL;
$message .= "ZJFVhALJwWV1uz8m1YoXXyvNqFMu4h7A94" . PHP_EOL;
$message .= "H7wVT/QJEd3xIonGorLsDxXHg8DE5byo9fcD5h/LHH02KX7nFKjyvH7AE7PjioCQid4qKOjuMh430G37gKIupDc=" . PHP_EOL;
$message .= "-----END ZETACOIN SIGNED MESSAGE-----";

$wallet = new Wallet();
$wallet->setNetworkPrefix("50");
$wallet->setNetworkName("Zetacoin");

echo $wallet->checkSignatureForRawMessage($message) ? 'Verifies' : 'Fails';
```

Note that the line endings are important since the parser is quite picky at the moment  This will be fixed in a later release.


If you don't want to bother with line endings, you can feed the components in manually:

```php
$message = "Test 1234";
$address = "ZJFVhALJwWV1uz8m1YoXXyvNqFMu4h7A94";
$signature = "H7wVT/QJEd3xIonGorLsDxXHg8DE5byo9fcD5h/LHH02KX7nFKjyvH7AE7PjioCQid4qKOjuMh430G37gKIupDc=";

$wallet = new Wallet();
$wallet->setNetworkPrefix("50");
$wallet->setNetworkName("Zetacoin");

echo $wallet->checkSignatureForMessage($address, $signature, $message) ? 'Verifies' : 'Fails';
```

If you find this usefull, please send me some to
 * Bitcoin: 1B6eyXVRPxdEitW5vWrUnzzXUy6o38P9wN
 * Zetacoin: ZK6kdE5H5q7H6QRNRAuqLF6RrVD4cFbiNX

The items in the repository may contain some derivative work based on Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt.

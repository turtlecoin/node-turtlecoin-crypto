[![NPM](https://nodei.co/npm/turtlecoin-crypto.png?downloads=true&stars=true)](https://nodei.co/npm/turtlecoin-crypto/)

[![Build Status](https://travis-ci.org/turtlecoin/turtlecoin-crypto.png?branch=master)](https://travis-ci.org/turtlecoin/turtlecoin-crypto)

# TurtleCoin Crypto Node Module

This project is designed to expose the necessary C++ cryptographic methods from the C++ libraries as a [Node.js C++ Addon](https://nodejs.org/docs/latest-v8.x/api/addons.html#addons_c_addons) thereby providing high performance Node.js access to necessary methods.

## Table of Contents

1. [Dependencies](#dependencies)
2. [Installation](#installation)
3. [Intialization](#intialization)

## Dependencies

* GCC-7 or higher (requires C++17 support)
* [NodeJS v8.x](https://nodejs.org) >= +8.x

### Windows

#### Prerequisites

Read very careful if you want this to work right the first time.

1) Open a *Windows Powershell* console as **Administrator**
2) Run the command: `npm install -g windows-build-tools --vs2015`
   ***This will take a while. Sit tight.***

## Installation

```bash
export CC=gcc-7
export CXX=g++-7
npm install turtlecoin-crypto
```

## Intialization

```javascript
const TurtleCoinCrypto = require('turtlecoin-crypto')
```

## Methods

The following methods are exposed via the module for use within your Node.js project(s).

## checkKey(publicKey)

Checks to verify that a public key is valid.

```javascript
const publicKey = 
  '0e5dc2885517e4aff187804e7eac350120a920108388c9740361ab96193b1773'
const valid = TurtleCoinCrypo.checkKey(publicKey)
```

Returns a boolean value of true/false.

## checkSignature(prefixHash, transactionPublicKey, signature)

```javascript
const prefixHash = 
  '0e5dc2885517e4aff187804e7eac350120a920108388c9740361ab96193b1773'
const transactionPublicKey = 
  '0dc7837fdf24e61194e424dd8ac8a3d297de8056751a2627e5204f892b6bdb58'
const signature = 
  'cfaeecf3bd68746b27826769b621b52518a9bed2c9ae46c97ac26a7d2b72110e'
const valid = TurtleCoinCrypo.checkSignature(
  prefixHash, transactionPublicKey, signature
)
```

*Example will not validate*

Returns a boolean value of true/false.

## derivePublicKey(derivation, outputIndex, transactionPublicKey)

Derives the public key from the supplied values:

```javascript
const derivation = 
    '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20'
const outputIndex = 2
const transactionPublicKey = 
    '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418'
const publicKey = TurtleCoinCrypto.derivePublicKey(
  derivation, outputIndex, transactionPublicKey
)
```

Returns the derived public key of the supplied values. Ex:

`bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d`

## deriveSecretKey()

Derives the secret key from the supplied values:

```javascript
const derivation = 
    '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20'
const outputIndex = 2
const transactionSecretKey = 
    '7684dcb378de24960838d1ab7328f01d4506ae2643d166710ff056304dca880a'
const secretKey = TurtleCoinCrypto.deriveSecretKey(
  derivation, outputIndex, transactionSecretKey
)
```

Returns the secret key of the supplied values. Ex:

`82dd5463fd25de745a78efde53eff28f333fbbfdde5be502bfbcb77e54dfb10d`

## generateKeyDerivation(secretKey, publicKey)

Generates a key derivation based on the supplied secret key and public key.

```javascript
const secretKey = 
  'e724c5905b0c8e3372adc58f0be04eb436dedb4e96998fcb509b2b3b82c8cbb6'
const publicKey = 
  '7bd90a13b4039743744682899dc61a7317b5ceced01d695cdeae6409cdc70803'
const derivation = TurtleCoinCrypto.generateKeyDerivation(secretKey, publicKey)
```

Returns the key derivation. Ex:

`a45bdbc86565a8917e31d4c2ac9cd32bf5f6702660505101528373392a373a4d`

## generateKeyImage(publicKey, secretKey)

Generates a keyImage based on the supplied public key and secret key.

```javascript
const publicKey = 
  'e724c5905b0c8e3372adc58f0be04eb436dedb4e96998fcb509b2b3b82c8cbb6'
const secretKey = 
  '7bd90a13b4039743744682899dc61a7317b5ceced01d695cdeae6409cdc70803'
const keyImage = TurtleCoinCrypto.generateKeyImage(publicKey, secretKey)
```

Returns the key image. Ex:

`157d58afd4cbe4a78a1d3843fb684b34e61c2707f9c350715b649637e2c38416`

## generateKeys()

Generates a random public and secret key pair

```javascript
const keys = TurtleCoinCrypo.generateKeys()
```

Example result below:

```javascript
{
  "publicKey": "0e5dc2885517e4aff187804e7eac350120a920108388c9740361ab96193b1773",
  "secretKey": "7684dcb378de24960838d1ab7328f01d4506ae2643d166710ff056304dca880a"
}
```

## secretKeyToPublicKey(secretKey)

Generates the public key from the secret key.

```javascript
const secretKey = '7684dcb378de24960838d1ab7328f01d4506ae2643d166710ff056304dca880a'
const publicKey = TurtleCoinCrypto.secretKeyToPublicKey(secretKey)
```

Returns the publicKey for the supplied secretKey. Ex:

`0e5dc2885517e4aff187804e7eac350120a920108388c9740361ab96193b1773`

## generateRingSignatures(prefixHash, keyImage, [inputKeys], transactionSecretKey, realInputIndex)

Generates the ring signatures for the supplied values

```javascript
const prefixHash = 
  '0e5dc2885517e4aff187804e7eac350120a920108388c9740361ab96193b1773'
const keyImage = 
  '0dc7837fdf24e61194e424dd8ac8a3d297de8056751a2627e5204f892b6bdb58'
const inputKeys = [
  '3c19e58e1f66e4887b2625adb99e242d28cbcff3e88e2255ebbf54b152733c58',
  '9810f855c7b484e0f8b5f5b358e3095ba0e6bc72bebf438a09892fea6388da74',
  '1380182bde2ea2fc7d70cf1264467db6c081d39bc9dea6f892c0a018a8fc8713',
  '2addb910073bb544889f0aa11c3b351a9e0282ce696d34bd638e2a9c57a9c3d7'
]
const transactionSecretKey = 
  '7684dcb378de24960838d1ab7328f01d4506ae2643d166710ff056304dca880a'
const realInputIndex = 2
const signatures = TurtleCoinCrypto.generateRingSignatures(
  prefixHash, keyImage, inputKeys, transactionSecretKey, realInputIndex
)
```

*Example code will not generate a valid set of signatures.*

Returns an array of signatures. Ex:

```javascript
[
  'bc86077e451cedeb5320d93a7783e1e693d058dcc174c14d1b55877c8222e40619924f2d4331e929701900fd4a2ad47b1838e5ed43a2cc319feae15da320540b',
  '4bf4ed9acb70ca43ffd2b8c3fb58eecb3a7d3230aaa19397f7a083c037e08c05f14b58258a3a3cbb880808eb33a72e934ffba22ecece2c16f2e64b1d000a9e03',
  '05d320145d1930d84e4785f410eba02a52144aecca335b9b733f63b257c5af0431ddbabe8c3460b1852f3fe7916e63ef2dd2e76c3a199fb84de0b4608ace4e0b',
  '03967e84fd936a3604360df7c39d0c94bcd9a72f327f0019dca34e196931c50be2ff10b93d1304866f400961c2bd921a02ad16e1f6c2f0966e5640a1651ad70f'
]
```

## generateSignature(prefixHash, publicKey, secretKey)

Generates the signature for a specific the supplied values:

```javascript
const prefixHash = 
  '0e5dc2885517e4aff187804e7eac350120a920108388c9740361ab96193b1773'
const publicKey = 
  '0dc7837fdf24e61194e424dd8ac8a3d297de8056751a2627e5204f892b6bdb58'
const secretKey = 
  'cfaeecf3bd68746b27826769b621b52518a9bed2c9ae46c97ac26a7d2b72110e'
const signature = TurtleCoinCrypo.generateSignature(
  prefixHash, publicKey, secretKey
)
```

Returns the signature generated from the supplied values. Ex:

`521028ce6bdc4a43cb4089433594360a6a843cdd72f2db292409e4bf6d7a7209ece1583e2c5db774f5986d1116c7c2291edecc7aeacf5cbe2f2e42d1d1cc1a0d`

## underivePublicKey(derivation, outputIndex, derivedKey)

Underives the public key from the supplied values

```javascript
const derivation = 
    '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20'
const outputIndex = 2
const derivedKey = 
    'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d'
const publicKey = TurtleCoinCrypto.underivePublicKey(
  derivation, outputIndex, derivedKey
)
```

Returns the underived public key of the supplied values: Ex.

`854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418`

# Hashing Algorithms

## cnFastHash(data)

Performs the cn_fast_hash function against the data

```javascript
const data =
  '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500'
const hash = TurtleCoinCrypto.cnFastHash(data)
```

Returns the hash of the supplied data. Ex:

`143416ef9aa00ba73a79b4847062a2574b754dcb297bed37c60dc095819cc309`

## cn_turtle_lite_slow_hash_v0(data)

Performs the cn_turtle_lite_slow_hash_v0 function against the data

```javascript
const data =
  '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500'
const hash = TurtleCoinCrypto.cn_turtle_lite_slow_hash_v0(data)
```

Returns the hash of the supplied data. Ex:

`a63000509161816b46a92c97615707bd1b409eec42ca7780e13956ca445cf65b`

## cn_turtle_lite_slow_hash_v1(data)

Performs the cn_turtle_lite_slow_hash_v1 function against the data

*Requires >= 43 bytes of data*

```javascript
const data =
  '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500323443'
const hash = TurtleCoinCrypto.cn_turtle_lite_slow_hash_v1(data)
```

Returns the hash of the supplied data. Ex:

`0ebed0c54f75f9cee9fdec55d37f6e3a7534e0f03e526368695197904d742355`

## cn_turtle_lite_slow_hash_v2(data)

Performs the cn_turtle_lite_slow_hash_v2 function against the data

*Requires >= 43 bytes of data*

```javascript
const data =
  '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500323443'
const hash = TurtleCoinCrypto.cn_turtle_lite_slow_hash_v2(data)
```

Returns the hash of the supplied data. Ex:

`6cf941d7d4764064ba752ed986bf4d1d33b52ab9ddf477cda827425234befcb8`


## License

```
Copyright (C) 2018-2019, The TurtleCoin Developers

Please see the included LICENSE file for more information.
```

'use strict'

const assert = require('assert')
const crypto = require('../')
const xmrigdata = '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02'

console.log('')
console.log('CryptoNight Tests')

const cnfasthash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0'

const cnfasthashdata = crypto.cnFastHash(xmrigdata)

console.log('')
console.log('[#1] Cryptonight Fast Hash: ', cnfasthashdata[1])
assert.deepStrictEqual(cnfasthashdata[1], cnfasthash)

console.log('')
console.log('Core Crypto Tests')

const testPrivateKey = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400'
const testPublicKey = '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac'

const derivedPublicKey = crypto.secretKeyToPublicKey(testPrivateKey)

console.log('')
console.log('[#2] Secret Key to Public Key')
console.log('     In Test Private Key: ', testPrivateKey)
console.log('     In Test Public Key: ', testPublicKey)
console.log('     Out Derived Public Key: ', derivedPublicKey[1])

assert(derivedPublicKey[1] === testPublicKey)

/* For reference, this is transaction fd9b0767c18752610833a8138e4bbb31d02b29bf50aa3af1557e2974a45c629c */
const txPublicKey = '3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94'

const walletPrivateViewKey = '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909'

/* Not using this right now, but will probably need this later to test something else */
const walletPrivateSpendKey = 'd9d555a892a85f64916cae1a168bd3f7f400b6471c7b12b438b599601298210b'

const walletPublicSpendKey = '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418'

var [err, derivation] = crypto.generateKeyDerivation(walletPrivateViewKey, txPublicKey)

const ourOutputIndex = 2

/* (First output) This is not our output. */
var publicSpendKey1
[err, publicSpendKey1] = crypto.underivePublicKey(derivation, 0, 'aae1b90b4d0a7debb417d91b7f7aa8fdfd80c42ebc6757e1449fd1618a5a3ff1')

console.log('')
console.log('[#3] Underive Public Key: False Test')
console.log('     Derived public spend key: ', publicSpendKey1)
console.log('     Our public spend key: ', walletPublicSpendKey)

assert(publicSpendKey1 !== walletPublicSpendKey && !err)

var publicSpendKey2
[err, publicSpendKey2] = crypto.underivePublicKey(derivation, ourOutputIndex, 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')

console.log('')
console.log('[#4] Underive Public Key: True Test')
console.log('     Derived public spend key: ', publicSpendKey2)
console.log('     Our public spend key: ', walletPublicSpendKey)

assert(publicSpendKey2 === walletPublicSpendKey && !err)

const expectedKeyImage = '5997cf23543ce2e05c327297a47f26e710af868344859a6f8d65683d8a2498b0'

var keyImage
[err, keyImage] = (() => {
  const [err1, publicKey] = crypto.derivePublicKey(derivation, ourOutputIndex, walletPublicSpendKey)

  const [err2, secretKey] = crypto.deriveSecretKey(derivation, ourOutputIndex, walletPrivateSpendKey)

  assert(!err1 && !err2)

  return crypto.generateKeyImage(publicKey, secretKey)
})()

console.log('')
console.log('[#5] Generate KeyImage')
console.log('     Generated key image: ', keyImage)
console.log('     Expected key image: ', expectedKeyImage)

assert(keyImage === expectedKeyImage && !err)

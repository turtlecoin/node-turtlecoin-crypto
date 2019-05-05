'use strict'

const assert = require('assert')
const crypto = require('../')
const xmrigdata = '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02'

console.log('')
console.log('CryptoNight Tests')

const cnfasthash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0'
// const xmrigcnturtlelitevariant0hash = '5e1891a15d5d85c09baf4a3bbe33675cfa3f77229c8ad66c01779e590528d6d3'
// const xmrigcnturtlelitevariant1hash = 'ae7f864a7a2f2b07dcef253581e60a014972b9655a152341cb989164761c180a'
// const xmrigcnturtlelitevariant2hash = 'b2172ec9466e1aee70ec8572a14c233ee354582bcb93f869d429744de5726a26'

const cnfasthashdata = crypto.cnFastHash(xmrigdata)
// const xmrigcnturtlelitevariant0data = crypto.cn_turtle_lite_slow_hash_v0(xmrigdata)
// const xmrigcnturtlelitevariant1data = crypto.cn_turtle_lite_slow_hash_v1(xmrigdata)
// const xmrigcnturtlelitevariant2data = crypto.cn_turtle_lite_slow_hash_v2(xmrigdata)

console.log('')
console.log('[#1] Cryptonight Fast Hash: ', cnfasthashdata[1])
assert.deepStrictEqual(cnfasthashdata[1], cnfasthash)
/*
console.log('[#2] Cryptonight Turtle Lite v0: ', xmrigcnturtlelitevariant0data)
assert.deepStrictEqual(xmrigcnturtlelitevariant0data, xmrigcnturtlelitevariant0hash)
console.log('[#3] Cryptonight Turtle Lite v1: ', xmrigcnturtlelitevariant1data)
assert.deepStrictEqual(xmrigcnturtlelitevariant1data, xmrigcnturtlelitevariant1hash)
console.log('[#4] Cryptonight Turtle Lite v2: ', xmrigcnturtlelitevariant2data)
assert.deepStrictEqual(xmrigcnturtlelitevariant2data, xmrigcnturtlelitevariant2hash)
*/

/*
console.log('')
console.log('Argon2 Tests')

const chukwa = 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e'

const chukwaData = crypto.chukwa(xmrigdata)

console.log('')
console.log('[#1] Chukwa: ', chukwaData)
assert.deepStrictEqual(chukwaData, chukwa)
*/

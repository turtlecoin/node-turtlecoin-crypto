'use strict'

const crypto = require('./')

console.log(crypto.generate_keys())

console.log(crypto.cn_fast_hash('0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02'))
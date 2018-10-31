# SYNOPSIS 
[![NPM Package](https://img.shields.io/npm/v/ethereumjs-tx.svg?style=flat-square)](https://www.npmjs.org/package/ethereumjs-tx)
[![Build Status](https://img.shields.io/travis/ethereumjs/ethereumjs-tx.svg?branch=master&style=flat-square)](https://travis-ci.org/ethereumjs/ethereumjs-tx)
[![Coverage Status](https://img.shields.io/coveralls/ethereumjs/ethereumjs-tx.svg?style=flat-square)](https://coveralls.io/r/ethereumjs/ethereumjs-tx)
[![Gitter](https://img.shields.io/gitter/room/ethereum/ethereumjs-lib.svg?style=flat-square)](https://gitter.im/ethereum/ethereumjs-lib) or #ethereumjs on freenode  

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)  

This repo is forked from [ethereumjs-tx](https://github.com/ethereumjs/ethereumjs-tx) package to perform transaction signing using a PKCS#11 cryptographic token.

# INSTALL
`npm install git+https://git@github.com/suenchunhui/ethereumjs-tx-pkcs11`

# USAGE
  - It is assumed that the cryptographic token is initalized and the appropriate driver is installed. Has been tested to work with [softhsm2](https://github.com/opendnssec/SoftHSMv2) and [Nitrokey token](https://shop.nitrokey.com/shop/product/nitrokey-hsm-7)
  - The user-pin(not so-pin) of the crypto-token is needed, and full path to the respective pkcs11 library.
  - [example](https://github.com/ethereumjs/ethereumjs-tx/blob/master/examples/transactions.js)

```javascript
const EthereumTx = require('ethereumjs-tx')

const txParams = {
  nonce: '0x00',
  gasPrice: '0x09184e72a000', 
  gasLimit: '0x2710',
  to: '0x0000000000000000000000000000000000000000', 
  value: '0x00', 
  data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057',
  // EIP 155 chainId - mainnet: 1, ropsten: 3
  chainId: 3
}

//PKCS parameters
var PKCSPath = "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so";
var pin = "USERPIN";

//persistent key pair generation
var keyPair_labels = tx.generatePKCS11Key(PKCSPath, pin);
console.log("Keypair labels:", keyPair_labels);	//generate a pair of public and private key label

const tx = new EthereumTx(txParams)
tx.signWithPKCS11(PKCSPath, pin, keyPair_labels.private);
console.log(tx.verifySignature())
const serializedTx = tx.serialize()
```

**Note:** this package expects ECMAScript 6 (ES6) as a minimum environment. From browsers lacking ES6 support, please use a shim (like [es6-shim](https://github.com/paulmillr/es6-shim)) before including any of the builds from this repo.


# BROWSER  
For a browser build please see https://github.com/ethereumjs/browser-builds.

# API
[./docs/](./docs/index.md)

# LICENSE
[MPL-2.0](https://tldrlegal.com/license/mozilla-public-license-2.0-(mpl-2))

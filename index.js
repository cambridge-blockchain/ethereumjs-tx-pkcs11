'use strict'
const ethUtil = require('ethereumjs-util')
const pkcs11js = require("pkcs11js");
const fees = require('ethereum-common/params.json')
const BN = ethUtil.BN
const retry_limit = 5;

// secp256k1n/2
const N_DIV_2 = new BN('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16)

/**
 * Creates a new transaction object.
 *
 * @example
 * var rawTx = {
 *   nonce: '00',
 *   gasPrice: '09184e72a000',
 *   gasLimit: '2710',
 *   to: '0000000000000000000000000000000000000000',
 *   value: '00',
 *   data: '7f7465737432000000000000000000000000000000000000000000000000000000600057',
 *   v: '1c',
 *   r: '5e1d3a76fbf824220eafc8c79ad578ad2b67d01b0c2425eb1f1347e8f50882ab',
 *   s: '5bd428537f05f9830e93792f90ea6a3e2d1ee84952dd96edbae9f658f831ab13'
 * };
 * var tx = new Transaction(rawTx);
 *
 * @class
 * @param {Buffer | Array | Object} data a transaction can be initiailized with either a buffer containing the RLP serialized transaction or an array of buffers relating to each of the tx Properties, listed in order below in the exmple.
 *
 * Or lastly an Object containing the Properties of the transaction like in the Usage example.
 *
 * For Object and Arrays each of the elements can either be a Buffer, a hex-prefixed (0x) String , Number, or an object with a toBuffer method such as Bignum
 *
 * @property {Buffer} raw The raw rlp encoded transaction
 * @param {Buffer} data.nonce nonce number
 * @param {Buffer} data.gasLimit transaction gas limit
 * @param {Buffer} data.gasPrice transaction gas price
 * @param {Buffer} data.to to the to address
 * @param {Buffer} data.value the amount of ether sent
 * @param {Buffer} data.data this will contain the data of the message or the init of a contract
 * @param {Buffer} data.v EC recovery ID
 * @param {Buffer} data.r EC signature parameter
 * @param {Buffer} data.s EC signature parameter
 * @param {Number} data.chainId EIP 155 chainId - mainnet: 1, ropsten: 3
 * */

class Transaction {
  constructor (data) {
    data = data || {}
    // Define Properties
    const fields = [{
      name: 'nonce',
      length: 32,
      allowLess: true,
      default: new Buffer([])
    }, {
      name: 'gasPrice',
      length: 32,
      allowLess: true,
      default: new Buffer([])
    }, {
      name: 'gasLimit',
      alias: 'gas',
      length: 32,
      allowLess: true,
      default: new Buffer([])
    }, {
      name: 'to',
      allowZero: true,
      length: 20,
      default: new Buffer([])
    }, {
      name: 'value',
      length: 32,
      allowLess: true,
      default: new Buffer([])
    }, {
      name: 'data',
      alias: 'input',
      allowZero: true,
      default: new Buffer([])
    }, {
      name: 'v',
      allowZero: true,
      default: new Buffer([0x1c])
    }, {
      name: 'r',
      length: 32,
      allowZero: true,
      allowLess: true,
      default: new Buffer([])
    }, {
      name: 's',
      length: 32,
      allowZero: true,
      allowLess: true,
      default: new Buffer([])
    }]

    /**
     * Returns the rlp encoding of the transaction
     * @method serialize
     * @return {Buffer}
     * @memberof Transaction
     * @name serialize
     */
    // attached serialize
    ethUtil.defineProperties(this, fields, data)

    /**
     * @property {Buffer} from (read only) sender address of this transaction, mathematically derived from other parameters.
     * @name from
     * @memberof Transaction
     */
    Object.defineProperty(this, 'from', {
      enumerable: true,
      configurable: true,
      get: this.getSenderAddress.bind(this)
    })

    // calculate chainId from signature
    let sigV = ethUtil.bufferToInt(this.v)
    let chainId = Math.floor((sigV - 35) / 2)
    if (chainId < 0) chainId = 0

    // set chainId
    this._chainId = chainId || data.chainId || 0
    this._homestead = true
  }

  /**
   * If the tx's `to` is to the creation address
   * @return {Boolean}
   */
  toCreationAddress () {
    return this.to.toString('hex') === ''
  }

  /**
   * Computes a sha3-256 hash of the serialized tx
   * @param {Boolean} [includeSignature=true] whether or not to inculde the signature
   * @return {Buffer}
   */
  hash (includeSignature) {
    if (includeSignature === undefined) includeSignature = true

    // EIP155 spec:
    // when computing the hash of a transaction for purposes of signing or recovering,
    // instead of hashing only the first six elements (ie. nonce, gasprice, startgas, to, value, data),
    // hash nine elements, with v replaced by CHAIN_ID, r = 0 and s = 0

    let items
    if (includeSignature) {
      items = this.raw
    } else {
      if (this._chainId > 0) {
        const raw = this.raw.slice()
        this.v = this._chainId
        this.r = 0
        this.s = 0
        items = this.raw
        this.raw = raw
      } else {
        items = this.raw.slice(0, 6)
      }
    }

    // create hash
    return ethUtil.rlphash(items)
  }

  /**
   * returns the public key of the sender
   * @return {Buffer}
   */
  getChainId () {
    return this._chainId
  }

  /**
   * returns the sender's address
   * @return {Buffer}
   */
  getSenderAddress () {
    if (this._from) {
      return this._from
    }
    const pubkey = this.getSenderPublicKey()
    this._from = ethUtil.publicToAddress(pubkey)
    return this._from
  }

  /**
   * returns the public key of the sender
   * @return {Buffer}
   */
  getSenderPublicKey () {
    if (!this._senderPubKey || !this._senderPubKey.length) {
      if (!this.verifySignature()) throw new Error('Invalid Signature')
    }
    return this._senderPubKey
  }

  /**
   * Determines if the signature is valid
   * @return {Boolean}
   */
  verifySignature () {
    const msgHash = this.hash(false)
    // All transaction signatures whose s-value is greater than secp256k1n/2 are considered invalid.
    if (this._homestead && new BN(this.s).cmp(N_DIV_2) === 1) {
      return false
    }

    try {
      let v = ethUtil.bufferToInt(this.v)
      if (this._chainId > 0) {
        v -= this._chainId * 2 + 8
      }
      this._senderPubKey = ethUtil.ecrecover(msgHash, v, this.r, this.s)
    } catch (e) {
      return false
    }

    return !!this._senderPubKey
  }

  /**
   * sign a transaction with a given a private key
   * @param {Buffer} privateKey
   */
  sign (privateKey) {
    const msgHash = this.hash(false)
    const sig = ethUtil.ecsign(msgHash, privateKey)
    if (this._chainId > 0) {
      sig.v += this._chainId * 2 + 8
    }
    Object.assign(this, sig)
  }


  randomLabel() {
      var text = "";
      const length = 16;
      var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      for(var i = 0; i < length; i++) {
          text += possible.charAt(Math.floor(Math.random() * possible.length));
      }
      return text;
  }
  /**
   * Create a key pair stored on HSM via PKCS11
   * @param {String} pin user-pin of PKCS11 token
   * @param {String} pkcsLibPath path to PKCS11 library SO file
   * @param {integer} slotIndex  card slot index to use (defaults to first one)
   */
  generatePKCS11Key(pkcsLibPath, pin, slotIndex = 0) {
    //init PKCS11
    var pkcs11 = new pkcs11js.PKCS11();
    pkcs11.load(pkcsLibPath);     
    pkcs11.C_Initialize();
     
    try {
        // Getting list of slots
        var slots = pkcs11.C_GetSlotList(true);
        var slot = slots[slotIndex];
        
        //start session
        var session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);
        pkcs11.C_Login(session, pkcs11js.CKU_USER, pin);  //TODO hardcoded to user type

        //generate key
        var key_label = this.randomLabel();
        var pub_label = key_label + "_PUB";
        var priv_label = key_label + "_PRI";
        var publicKeyTemplate = [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
            { type: pkcs11js.CKA_TOKEN, value: true },  //persistent key
            { type: pkcs11js.CKA_LABEL, value: pub_label },
            { type: pkcs11js.CKA_EC_PARAMS, value: new Buffer("06052b8104000a", "hex") }, // secp256k1(AKA P-256)
        ];
        var privateKeyTemplate = [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
            { type: pkcs11js.CKA_TOKEN, value: true },  //persistent key
            { type: pkcs11js.CKA_LABEL, value: priv_label },
            { type: pkcs11js.CKA_SIGN, value: true },
            { type: pkcs11js.CKA_DERIVE, value: true },
        ];
        var keys = pkcs11.C_GenerateKeyPair(
          session, 
          { mechanism: pkcs11js.CKM_EC_KEY_PAIR_GEN }, 
          publicKeyTemplate, privateKeyTemplate);

        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);
        return {public: pub_label, private: priv_label};
    }
    catch(e){
        console.error(e);
    }
    finally {
        pkcs11.C_Finalize();
    }
  }



  /**
   * get raw public key component via PKCS11 key handle
   * @param {String}  pkcsLibPath path to PKCS11 library SO file
   * @param {String} pin user-pin of PKCS11 token
   * @param {String}  key_label prefix of key pair token label created from generatePKCS11Key()
   * @param {integer} slotIndex  card slot index to use (defaults to first one)
   */
  getPublicKeyPKCS11 (pkcsLibPath, pin, key_label, slotIndex = 0) {
    var pkcs11 = new pkcs11js.PKCS11();
    pkcs11.load(pkcsLibPath);     
    pkcs11.C_Initialize();
     
    try {
        // Getting list of slots
        var slots = pkcs11.C_GetSlotList(true);
        var slot = slots[slotIndex];
        
        //start session
        var session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);
     
        // Getting info about Session
        pkcs11.C_Login(session, pkcs11js.CKU_USER, pin);  //TODO hardcoded to user type

        //find key
        pkcs11.C_FindObjectsInit(session, 
          [
            { type: pkcs11js.CKA_LABEL, value: key_label },
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY }
          ]);

        var publicKey = pkcs11.C_FindObjects(session);
        pkcs11.C_FindObjectsFinal(session);
        if (publicKey == null) {
          //FIXME assert key found
          throw "Key not found";
        }

        var ecpoint = pkcs11.C_GetAttributeValue(session, publicKey, [{type: pkcs11js.CKA_EC_POINT}]);
        var ecdata = ecpoint[0].value;
        var prefix = "02";
        if (ecdata[66] % 2 == 1)
          prefix = "03";

        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);

        return new Buffer(prefix + ecdata.slice(3,35).toString('hex'),'hex');
    }
    catch(e){
        console.error(e);
    }
    finally {
        pkcs11.C_Finalize();
    }
  }

  /**
   * sign a transaction with a private key on HSM via PKCS11
   * @param {String}  pkcsLibPath path to PKCS11 library SO file
   * @param {String} pin user-pin of PKCS11 token
   * @param {String}  key_label prefix of key pair token label created from generatePKCS11Key()
   * @param {integer} slotIndex  card slot index to use (defaults to first one)
   */
  signWithPKCS11 (pkcsLibPath, pin, key_label, slotIndex = 0) {

    var pkcs11 = new pkcs11js.PKCS11();
    pkcs11.load(pkcsLibPath);     
    pkcs11.C_Initialize();
     
    try {
        // Getting list of slots
        var slots = pkcs11.C_GetSlotList(true);
        var slot = slots[slotIndex];
        
        //start session
        var session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);
     
        // Login
        pkcs11.C_Login(session, pkcs11js.CKU_USER, pin);  //FIXME hardcoded to user type

        //find key
        pkcs11.C_FindObjectsInit(session, [{ type: pkcs11js.CKA_LABEL, value: key_label }]);

        var privateKey = pkcs11.C_FindObjects(session);
        pkcs11.C_FindObjectsFinal(session);

        //hashing
        const msgHash = this.hash(false)

        //signing
        var sigVerified = false;
        //retry signature generation in case s-value is greater than secp256k1n/2
        for(var retry=0; retry < retry_limit; retry++){ 
          pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_ECDSA }, privateKey);     
          var pkcs_sig = pkcs11.C_Sign(session, msgHash, Buffer(256));
          var sig = {r: pkcs_sig.slice(0,32), s:pkcs_sig.slice(32,64)};
          
          sig.v = 27;
          if (this._chainId > 0) {
            sig.v += this._chainId * 2 + 8
          }

          //recid is range from 0..3
          //FIXME are we able to calculate this from public key only?
          for(var recid=0; recid<4; recid++){
            Object.assign(this, sig);
            if(this.verifySignature()) {
              sigVerified = true;
              break;
            }
            sig.v++;
          }

          if(sigVerified){
            break;
          }
        }

        if(!sigVerified){
          throw "Unable to create valid signature (within "+retry_limit+" retries)";
        }

        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);
    }
    catch(e){
        console.error(e);
    }
    finally {
        pkcs11.C_Finalize();
    }
  }

  /**
   * The amount of gas paid for the data in this tx
   * @return {BN}
   */
  getDataFee () {
    const data = this.raw[5]
    const cost = new BN(0)
    for (let i = 0; i < data.length; i++) {
      data[i] === 0 ? cost.iaddn(fees.txDataZeroGas.v) : cost.iaddn(fees.txDataNonZeroGas.v)
    }
    return cost
  }

  /**
   * the minimum amount of gas the tx must have (DataFee + TxFee + Creation Fee)
   * @return {BN}
   */
  getBaseFee () {
    const fee = this.getDataFee().iaddn(fees.txGas.v)
    if (this._homestead && this.toCreationAddress()) {
      fee.iaddn(fees.txCreation.v)
    }
    return fee
  }

  /**
   * the up front amount that an account must have for this transaction to be valid
   * @return {BN}
   */
  getUpfrontCost () {
    return new BN(this.gasLimit)
      .imul(new BN(this.gasPrice))
      .iadd(new BN(this.value))
  }

  /**
   * validates the signature and checks to see if it has enough gas
   * @param {Boolean} [stringError=false] whether to return a string with a dscription of why the validation failed or return a Bloolean
   * @return {Boolean|String}
   */
  validate (stringError) {
    const errors = []
    if (!this.verifySignature()) {
      errors.push('Invalid Signature')
    }

    if (this.getBaseFee().cmp(new BN(this.gasLimit)) > 0) {
      errors.push([`gas limit is too low. Need at least ${this.getBaseFee()}`])
    }

    if (stringError === undefined || stringError === false) {
      return errors.length === 0
    } else {
      return errors.join(' ')
    }
  }
}

module.exports = Transaction

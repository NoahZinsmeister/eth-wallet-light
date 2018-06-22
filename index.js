const bip39 = require('bip39')
const CryptoJS = require('crypto-js')
const ethUtil = require('ethereumjs-util')
const hdkey = require('ethereumjs-wallet/hdkey')

const keySize = 32
const iterations = 100
const AESBlockSize = 16

module.exports.isMnemonicValid = (mnemonic) => {
  return bip39.validateMnemonic(mnemonic)
}

module.exports.concatSignature = (signature) => {
  var r = signature.r
  var s = signature.s
  var v = signature.v
  r = ethUtil.fromSigned(r)
  s = ethUtil.fromSigned(s)
  v = ethUtil.bufferToInt(v)
  r = ethUtil.setLengthLeft(ethUtil.toUnsigned(r), 32).toString('hex')
  s = ethUtil.setLengthLeft(ethUtil.toUnsigned(s), 32).toString('hex')
  v = ethUtil.stripHexPrefix(ethUtil.intToHex(v))
  return ethUtil.addHexPrefix(r.concat(s, v).toString('hex'))
}

module.exports.Keystore = class Keystore {
  constructor (rng) {
    // rng should be a function that accepts a number of bytes argument and returns an unprefixed hex string
    // see https://github.com/brix/crypto-js/issues/7 for CryptoJS random
    var native = (bytes) => { return CryptoJS.lib.WordArray.random(bytes).toString() }
    this.rng = rng || native
  }

  async initializeFromEntropy (entropy, password) {
    if (typeof entropy !== 'string' || typeof password !== 'string') {
      throw new Error('entropy and password must both be strings')
    }

    // generate extra randomness
    var extraEntropy = await this.rng(keySize)
    // hash the entropy sources together and take first the 16 bytes (corresponds to 12 seed words)
    var hashedEntropy = ethUtil.sha256(entropy + extraEntropy).slice(0, 16)
    var mnemonic = bip39.generateMnemonic(undefined, () => { return hashedEntropy })

    await this.restoreFromMnemonic(mnemonic, password)
  }

  async restoreFromMnemonic (mnemonic, password) {
    if (typeof mnemonic !== 'string' || typeof password !== 'string') {
      throw new Error('mnemonic and password must both be strings')
    }
    if (!module.exports.isMnemonicValid(mnemonic)) throw new Error('invalid mnemonic')

    var seed = bip39.mnemonicToSeed(mnemonic)
    var wallet = hdkey.fromMasterSeed(seed).derivePath(`m/44'/60'/0'/0`).deriveChild(0).getWallet()

    // salt should be the same size as the hash function output, sha256 in this case i.e. 32 bytes
    this.salt = await this.rng(keySize)
    var key = this.keyFromPassword(password)
    this.address = wallet.getAddressString()
    this.encodedMnemonic = await this.encryptString(mnemonic, key)
    this.encodedPrivateKey = await this.encryptString(wallet.getPrivateKeyString(), key)
  }

  restorefromSerialized (serializedKeystore) {
    var variables = JSON.parse(serializedKeystore)
    this.salt = variables.salt
    this.address = variables.address
    this.encodedMnemonic = variables.encodedMnemonic
    this.encodedPrivateKey = variables.encodedPrivateKey
  }

  keyFromPassword (password) {
    return CryptoJS.PBKDF2(password, this.salt, {
      keySize: keySize / 4, // 1 word := 4 bytes
      hasher: CryptoJS.algo.SHA256,
      iterations: iterations
    })
  }

  async encryptString (string, password) {
    var randomBytes = await this.rng(AESBlockSize)
    var words = []
    for (var i = 0; i < AESBlockSize * 2; i += 8) {
      words.push('0x' + randomBytes.substring(i, i + 8))
    }
    var iv = new CryptoJS.lib.WordArray.init(words, AESBlockSize)
    var ciphertext = CryptoJS.AES.encrypt(string, this.keyFromPassword(password), { iv: iv })

    return {
      ciphertext: ciphertext.toString(),
      iv: iv
    }
  }

  decryptString (encrypted, password) {
    var decrypted = CryptoJS.AES.decrypt(encrypted.ciphertext, this.keyFromPassword(password), { iv: encrypted.iv })
    return decrypted.toString(CryptoJS.enc.Utf8)
  }

  serialize () {
    return JSON.stringify({
      salt: this.salt,
      address: this.address,
      encodedMnemonic: this.encodedMnemonic,
      encodedPrivateKey: this.encodedPrivateKey
    })
  }

  signMessageHash (messageHash, password) {
    var privateKey = this.getPrivateKey(password)
    return ethUtil.ecsign(
      Buffer.from(ethUtil.stripHexPrefix(messageHash), 'hex'),
      Buffer.from(privateKey.substring(2), 'hex')
    )
  }

  getMnemonic (password) {
    return this.decryptString(this.encodedMnemonic, this.keyFromPassword(password))
  }

  getPrivateKey (password) {
    return this.decryptString(this.encodedPrivateKey, this.keyFromPassword(password))
  }
}

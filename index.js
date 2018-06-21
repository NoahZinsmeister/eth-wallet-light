const bip39 = require('bip39')
const CryptoJS = require('crypto-js')
const ethUtil = require('ethereumjs-util')
const hdkey = require('ethereumjs-wallet/hdkey')

class Keystore {
  initialize (entropy, password) {
    var hashedEntropy = ethUtil.sha256(entropy).slice(0, 16);

    var mnemonic = bip39.generateMnemonic(undefined, () => { return hashedEntropy })
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error("invalid mnemonic")
    }

    var seed = bip39.mnemonicToSeed(mnemonic)
    var hdWallet = hdkey.fromMasterSeed(seed).derivePath(`m/44'/60'/0'/0`)
    var wallet = hdWallet.deriveChild(0).getWallet()

    this.address = wallet.getAddressString()
    this.encodedPrivateKey = this.encryptString(wallet.getPrivateKeyString(), password)
    this.encodedMnemonic = this.encryptString(mnemonic, password)
  }

  encryptString (string, password) {
    var ciphertext = CryptoJS.AES.encrypt(string, password)
    return ciphertext.toString()
  }

  decryptString (ciphertext, password) {
    var bytes = CryptoJS.AES.decrypt(ciphertext, password)
    var plaintext = bytes.toString(CryptoJS.enc.Utf8)
    return plaintext
  }

  serialize () {
    return JSON.stringify({
      publicKey: this.publicKey,
      encodedPrivateKey: this.encodedPrivateKey,
      encodedMnemonic: this.encodedMnemonic
    })
  }

  fromSerialized (serializedKeystore) {
    var variables = JSON.parse(serializedKeystore)
    this.publicKey = variables.publicKey,
    this.encodedPrivateKey = variables.encodedPrivateKey,
    this.encodedMnemonic = variables.encodedMnemonic
  }

  signMessageHash (msgHash, password) {
    var privateKey = this.getPrivateKey(password)
    return ethUtil.ecsign(
      Buffer.from(ethUtil.stripHexPrefix(signMessageHash), 'hex'),
      Buffer.from(privKey.substring(2), 'hex')
    )
  }

  getMnemonic (password) {
    var mnemonic = this.decryptString(this.encodedMnemonic, password)
    return mnemonic
  }

  getPrivateKey (password) {
    var privateKey = this.decryptString(this.encodedPrivateKey, password)
    return privateKey
  }
}

var concatSignature = (signature) => {
  var r = signature.r;
  var s = signature.s;
  var v = signature.v;
  r = ethUtil.fromSigned(r);
  s = ethUtil.fromSigned(s);
  v = ethUtil.bufferToInt(v);
  r = ethUtil.setLengthLeft(ethUtil.toUnsigned(r), 32).toString('hex');
  s = ethUtil.setLengthLeft(ethUtil.toUnsigned(s), 32).toString('hex');
  v = ethUtil.stripHexPrefix(ethUtil.intToHex(v));
  return ethUtil.addHexPrefix(r.concat(s, v).toString("hex"));
}

module.exports = {
  Keystore: Keystore,
  concatSignature: concatSignature
}

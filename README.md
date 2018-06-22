# eth-wallet-light

A lightweight Ethereum wallet with bip39 seed words. Sensitive data in keystores, either in memory or serialized, are always securely encrypted. Keystores can optionally be initialized with a custom RNG. **THIS IS HIGHLY RECOMMENDED**, as the default RNG used is not a CSPRNG.

## Installation

`npm install NoahHydro/eth-wallet-light`

`const wallet = require('eth-wallet-light')`

## General Functions
### wallet.isMnemonicValid(mnemonic)
Checks the validity of the passed mnemonic.

**Options**
- mnemonic (required): A 12-word bip39 seed phrase.

### wallet.concatSignature(signature)
Concatenates the output of `keystore.signMessageHash` into a single hex string.

**Options**
- signature (required): A signature object.

## `Keystore` functions

### new wallet.Keystore(rng)
This is the constructor for new keystores. Does not create a keypair.

**Options**
- rng (optional): A function with one argument (the number of bytes), which must return a random hex string of that many bytes (`0x` prefix optional). Defaults to a non-secure RNG provided by [crypto-js](https://github.com/brix/crypto-js) if not passed.

**Returns** Keystore

### keystore.initializeFromEntropy(entropy, password)
This method initializes a new keystore. Creates a keypair.

**Options**
- entropy (required): A string of entropy. Will be hashed with 32 bytes of output from the keystore's `rng` to produce 16 bytes of randomness that is fed to the bip39 mnemonic generator.
- password (required): A string password that will be fed to PBKDF2 to produce a key that will encrypt the sensitive contents of the keystore.

**Returns** Promise(Keystore)

### keystore.restoreFromMnemonic(mnemonic, password)
This method initializes a new keystore. Enables a keypair gneerated from the mnemonic.

**Options**
- menemonic (required): 12 bip39-compliant seed words. Can be used to recover backed-up or new accounts.
- password (required): A string password that will be fed to PBKDF2 to produce a key that will encrypt the sensitive contents of the keystore.

**Returns** Promise(Keystore)

### keystore.restorefromSerialized(serializedKeystore)
This method restores a keystore from serialization.

**Options**
- serializedKeystore (required): The output of `keystore.serialize()`.

**Returns** Keystore

### keystore.serialize()
This method serializes a keystore into a string.

**Returns** String

### keystore.signMessageHash(messageHash, password)
Sign a message with the keystore's private key.

**Options**
- messageHash (required): A hex-encoded 32-byte message. The `0x` prefix is optional (it is stripped out).
- password (required): The password that encrypts the contents of the keystore.

**Returns** String

### keystore.getMnemonic(password)
Get the mnemonic from the keystore.

**Options**
- password (required): The password that encrypts the contents of the keystore.

**Returns** String

### keystore.getPrivateKey(password)
Get the private key from the keystore.

**Options**
- password (required): The password that encrypts the contents of the keystore.

**Returns** String

### keystore.getAddress()
Get the public address from the keystore.

**Returns** String

## Sample Code

```javascript
const wallet = require('eth-wallet-light')
const crypto = require('crypto') // in react native, this should be react-native-securerandom

// helper function to log keystore variables
var logKeystoreVariables = (title, keystore) => {
  console.log(title)
  console.log('-'.repeat(title.length))
  console.log('Address: ', keystore.getAddress())
  console.log('Mnemonic: ', keystore.getMnemonic(password))
  console.log('Private Key: ', keystore.getPrivateKey(password))
  console.log('Signature:', wallet.concatSignature(keystore.signMessageHash(msgHash, password)))
  console.log('\n')
}

var msgHash = '0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658'
var password = 'mypassword'
var entropy = '2o3uhrb2i3pbrq32b'
var csprng = (bytes) => { return crypto.randomBytes(bytes).toString('hex') } // this will vary

var defaultRNG = {}
var userRNG = {}

var main = async () => {
  // initialize using default rng
  defaultRNG.keystore = await new wallet.Keystore().initializeFromEntropy(entropy, password)
  logKeystoreVariables('Default RNG Initialization', defaultRNG.keystore)

  // initialize using user-provided rng
  userRNG.keystore = await new wallet.Keystore(csprng).initializeFromEntropy(entropy, password)
  logKeystoreVariables('User Provided RNG Initialization', userRNG.keystore)

  // serialize to string
  defaultRNG.serialized = defaultRNG.keystore.serialize()
  userRNG.serialized = userRNG.keystore.serialize()

  // recover from serialized
  defaultRNG.fromSerialized = await new wallet.Keystore().restorefromSerialized(defaultRNG.serialized)
  userRNG.fromSerialized = await new wallet.Keystore(csprng).restorefromSerialized(userRNG.serialized)

  // ensure serialization was consistent
  logKeystoreVariables('Default RNG From Serialized', defaultRNG.fromSerialized)
  logKeystoreVariables('User Provided RNG From Serialized', userRNG.fromSerialized)

  // recover from mnemonic
  defaultRNG.mnemonic = defaultRNG.fromSerialized.getMnemonic(password)
  defaultRNG.fromMnemonic = await new wallet.Keystore().restoreFromMnemonic(defaultRNG.mnemonic, password)
  userRNG.mnemonic = userRNG.fromSerialized.getMnemonic(password)
  userRNG.fromMnemonic = await new wallet.Keystore(csprng).restoreFromMnemonic(userRNG.mnemonic, password)

  // ensure mnemonic recovery was consistent
  logKeystoreVariables('Default RNG From Mnemonic', defaultRNG.fromMnemonic)
  logKeystoreVariables('User Provided RNG From Mnemonic', userRNG.fromMnemonic)
}

main()
```

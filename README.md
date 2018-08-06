# eth-wallet-light

A lightweight, pure JS Ethereum wallet optimized for mobile. Inspired in part by the Consensys [eth-lightwallet](https://github.com/ConsenSys/eth-lightwallet). **This code has not been independently audited, use at your own risk**. Features include:
- No dependency on the Node crypto module. This fact makes the library ideal for use in e.g. React Native.
- BIP39 seed words, from a [fork of the canonical library](https://github.com/NoahHydro/bip39) that removes dependency on Node crypto.
- Keystores, when stored in-memory or as serialized keystore objects, are always securely encrypted with PBKDF2. All functions accessing sensitive information require a password.
- Keystores can optionally be initialized with a custom RNG for additional randomness. **THIS IS HIGHLY RECOMMENDED**, as the default RNG used is not a CSPRNG.

## Installation

`npm install NoahHydro/eth-wallet-light`

`const wallet = require('eth-wallet-light')`

## General Functions
### wallet.isMnemonicValid(mnemonic)
Checks the validity of the passed mnemonic.

**Options**
- mnemonic (required): A 12-word BIP39 seed phrase.

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
This method initializes a keystore with a new random keypair. The password is used to encrypt the initialized keystore.

**Options**
- entropy (required): A string of entropy. Will be hashed with 32 bytes of output from the keystore's `rng` to produce 16 bytes of randomness that is fed to the BIP39 mnemonic generator.
- password (required): A string password that will be fed to PBKDF2 to produce a key that will encrypt the sensitive contents of the keystore.

**Returns** Promise(Keystore)

### keystore.restoreFromMnemonic(mnemonic, password)
This method initializes a keystore, restoring a keypair from a mnemonic. The password is used to encrypt the initialized keystore.

**Options**
- menemonic (required): 12 BIP39-compliant seed words. Can be used to recover backed-up or new accounts.
- password (required): A string password that will be fed to PBKDF2 to produce a key that will encrypt the sensitive contents of the keystore.

**Returns** Promise(Keystore)

### keystore.restorefromSerialized(serializedKeystore)
This method restores a keystore from serialization. Note that when restoring from a serialized keystore, the `rng` argument to the keystore constructor is unnecessary, and can safely be left as `undefined`.

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

Check [`test/test.js`](./test/test.js) for exhaustive usage examples. Some starter code:

```javascript
const wallet = require('eth-wallet-light')

const password = 'mypassword' // this should be a real password

var keystore = await new wallet.Keystore().initializeFromEntropy(entropy, password)
console.log('Address: ', keystore.getAddress())

var messageHash = '0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658'
var signature = wallet.concatSignature(keystore.signMessageHash(messageHash, password))
console.log('Signature:', signature)
```

In Node, here are two example `rng` functions that are both CSPRNGs. In React Native, this code should instead rely on something like [react-native-securerandom](https://github.com/rh389/react-native-securerandom).

```javascript
const crypto = require('crypto')

const csprng = (bytes) => { return crypto.randomBytes(bytes).toString('hex') }
const csprngPromise = (bytes) => {
  return new Promise(function(resolve, reject) {
    crypto.randomBytes(bytes, (err, buf) => {
      err ? reject(err) : resolve(buf.toString('hex'))
    })
  })
}

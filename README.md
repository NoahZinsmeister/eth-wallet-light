# eth-wallet-light

## Installation

`npm install NoahHydro/eth-wallet-light`

## Sample Code
Keystores can optionally be initialized with a custom RNG function whose argument is the number of bytes, and returns a random hex string of that many bytes **without the 0x prefix**. THIS IS HIGHLY RECOMMENDED, as the default RNG used is not a CSPRNG.

```javascript
const ethWalletLight = require('eth-wallet-light')
const crypto = require('crypto') // in react native, this should be react-native-securerandom

// helper function to log keystore variables
var logKeystoreVariables = (title, keystore) => {
  console.log(title)
  console.log('-'.repeat(title.length))
  console.log('Address: ', keystore.address)
  console.log('Mnemonic: ', keystore.getMnemonic(password))
  console.log('Private Key: ', keystore.getPrivateKey(password))
  console.log('Signature:', ethWalletLight.concatSignature(keystore.signMessageHash(msgHash, password)))
  console.log("\n")
}

var msgHash = '0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658'
var password = 'mypassword'
var entropy = '2o3uhrb2i3pbrq32b'
var csprng = (bytes) => { return crypto.randomBytes(bytes).toString('hex') } // this will vary

var defaultRNG = {}
var userProvidedRNG = {}

main = async () => {
  // initialize using default rng
  defaultRNG.keystore = new ethWalletLight.Keystore()
  await defaultRNG.keystore.initialize(entropy, password)
  logKeystoreVariables('Default RNG Initialization', defaultRNG.keystore)

  // initialize using user-provided rng
  userProvidedRNG.keystore = new ethWalletLight.Keystore(csprng)
  await userProvidedRNG.keystore.initialize(entropy, password)
  logKeystoreVariables('User Provided RNG Initialization', userProvidedRNG.keystore)

  // serialize to string
  defaultRNG.serialized = defaultRNG.keystore.serialize()
  userProvidedRNG.serialized = userProvidedRNG.keystore.serialize()

  // recover from serialized
  defaultRNG.fromSerialized = new ethWalletLight.Keystore()
  defaultRNG.fromSerialized.fromSerialized(defaultRNG.serialized)
  userProvidedRNG.fromSerialized = new ethWalletLight.Keystore(csprng)
  userProvidedRNG.fromSerialized.fromSerialized(userProvidedRNG.serialized)

  // ensure serialization was consistent
  logKeystoreVariables('Default RNG From Serialized', defaultRNG.fromSerialized)
  logKeystoreVariables('User Provided RNG From Serialized', userProvidedRNG.fromSerialized)
}

main()
```

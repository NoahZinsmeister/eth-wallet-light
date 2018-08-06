const wallet = require('../')
const crypto = require('crypto') // in react native, this could be e.g. react-native-securerandom
const assert = require('chai').assert

// ensure keystores variables are equal
const compareKeystores = (keystore1, keystore2, errorMessage) => {
  assert.equal(keystore1.getAddress(), keystore2.getAddress(), `Unequal addresses: ${errorMessage}`)
  assert.equal(keystore1.getMnemonic(password), keystore2.getMnemonic(password), `Unequal mnemonics: ${errorMessage}`)
  assert.equal(
    keystore1.getPrivateKey(password),
    keystore2.getPrivateKey(password),
    `Unequal private keys: ${errorMessage}`
  )
  assert.equal(
    wallet.concatSignature(keystore1.signMessageHash(messageHash, password)),
    wallet.concatSignature(keystore2.signMessageHash(messageHash, password)),
    `Unequal signatures: ${errorMessage}`
  )
}

// define CSPRNGs for node
const csprng = (bytes) => { return crypto.randomBytes(bytes).toString('hex') }
const csprngPromise = (bytes) => {
  return new Promise(function (resolve, reject) {
    crypto.randomBytes(bytes, (err, buf) => {
      err ? reject(err) : resolve(buf.toString('hex'))
    })
  })
}
const rngTypes = {
  default: undefined,
  csprng: csprng,
  csprngPromise: csprngPromise
}

// variables specific to the test
const entropy = 'hydro' // in reality, this should be a different string of true entropy for each keystore!
const password = 'mypassword' // in reality, this should be better!
const keystores = {}
const messageHash = '0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658'

describe('Eth Wallet Light', function () {
  describe('testing initialization', function () {
    Object.keys(rngTypes).map(type => {
      it(`can be initialized from ${type}`, async function () {
        keystores[type] = await new wallet.Keystore(rngTypes[type]).initializeFromEntropy(entropy, password)
      })
    })
  })

  describe('testing serialization', function () {
    it('can be serialized', function () {
      Object.keys(rngTypes).map(type => {
        keystores[`${type}Serialized`] = keystores[type].serialize()
      })
    })

    it('can be deserialized', function () {
      Object.keys(rngTypes).map(type => {
        keystores[`${type}FromSeserialized`] =
          new wallet.Keystore().restorefromSerialized(keystores[`${type}Serialized`])
      })
    })

    it('ensure that information was not lost in serialization', async function () {
      Object.keys(rngTypes).map(type => {
        compareKeystores(keystores[type], keystores[`${type}FromSeserialized`], type)
      })
    })
  })

  describe('testing mnemonic', function () {
    it('can be recovered from mnemonic', function () {
      Object.keys(rngTypes).map(async type => {
        assert.isTrue(wallet.isMnemonicValid(keystores[type].getMnemonic(password)), 'invalid mnemonic')
        // the rng argument does nothing here, we don't need to pass it
        keystores[`${type}FromMnemonic`] =
          await new wallet.Keystore().restoreFromMnemonic(keystores[type].getMnemonic(password), password)
      })
    })

    it('ensure that information was not lost in recovery', async function () {
      Object.keys(rngTypes).map(type => {
        compareKeystores(keystores[type], keystores[`${type}FromMnemonic`], type)
      })
    })
  })
})

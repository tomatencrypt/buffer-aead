# buffer-aead

[![npm package](https://nodei.co/npm/buffer-aead.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/buffer-aead/)

[![npm](https://img.shields.io/npm/v/buffer-aead)](https://www.npmjs.com/package/buffer-aead) [![QA](https://github.com/tomatencrypt/buffer-aead/actions/workflows/qa.yml/badge.svg?branch=main)](https://github.com/tomatencrypt/buffer-aead/actions/workflows/qa.yml)

Buffer encryption, using aead (authenticated encryption with associated data), powered by strong crypto algorithms, written in typescrypt

## install
```shell
npm i buffer-aead
```

___

## Supported aead algorithms/suites
* AES-256-CTR with HMAC-SHA256 (not recommended)
* AES-GCM
* AES-CCM (plaintext limited to be less than 64 KiB)
* ChaCha20-Poly1305
* XChaCha20-Poly1305

___

## Quick example (AES-256-GCM):
```js
import { aes256Gcm } from 'buffer-aead'
const { key, nonce, ciphertext, authTag } = aes256Gcm.encrypt({ data });
const decrypted = aes256Gcm.decrypt({ key, nonce, ciphertext, authTag });
```

___

## Usage
Detailed How-To with examples.

### Available AEADs
Currently the following aead algorithms are supported

* AES in Galois Counter Mode
  * with 128 bit key size: `import { aes128gcm } from 'buffer-aead'`
  * with 192 bit key size: `import { aes192gcm } from 'buffer-aead'`
  * with 256 bit key size: `import { aes256gcm } from 'buffer-aead'`
* AES in CCM (Counter Mode with CBC-Mac)
  Important: For this AEAD the plaintext is limtted to be less than 64 KiB (65536 bytes)
  * with 128 bit key size: `import { aes128ccm } from 'buffer-aead'`
  * with 192 bit key size: `import { aes192ccm } from 'buffer-aead'`
  * with 256 bit key size: `import { aes256ccm } from 'buffer-aead'`
* AES-256 in CTR (Counter Mode) with HMAC (SHA-256): `import { aesctrhmac } from 'buffer-aead'` (not recommended)
* chacha20 with poly1305: `import { chacha20poly1305 } from 'buffer-aead'`
* xchacha20 with poly1305: `import { xchacha20poly1305 } from 'buffer-aead'`

### key/nonce generation
To simplify key/nonce generation, force correct length and prevent miss-use, there are two helper functions:
* `keyGen`: Returns a key, appropriate to the particular AEAD
* `nonceGen`: Returns a nonce (number only used once, aka IV (Initial Vector)), appropriate to the particular AEAD

#### Example, using chacha20-poly1305
```js
import { chacha20poly1305 } from 'buffer-aead';
const key = chacha20poly1305.keyGen();
const nonce = chacha20poly1305.nonceGen();
```

### encrypt and decrypt
each aead object (aes256gcm, for example) provides 2 main functions:
* `encrypt`
  * takes an `EncryptionInput` object
  * returns an `EncryptionOutput` object
* `decrypt`
  * takes a `DecryptionInput` object
  * returns a `Buffer`

See [Inputs/Outputs](#inputsoutputs) for details.

#### Examples, using AES-256-GCM

##### provide data to encrypt (key and noce will be generated inside encrypt function)
```js
import { aes256gcm } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const { key, nonce, ciphertext, authTag } = aes256gcm.encrypt({ data });
const decrypted = aes256gcm.decrypt({ key, nonce, ciphertext, authTag });
```

##### provide data and key (nonce will be generated inside encrypt function)
```js
import { aes256gcm } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const key = aes256gcm.keyGen();
const { nonce, ciphertext, authTag } = aes256gcm.encrypt({ data, key });
const decrypted = aes256gcm.decrypt({ key, nonce, ciphertext, authTag });
```

##### provide data and nonce (key will be generated inside encrypt function)
```js
import { aes256gcm } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const nonce = aes256gcm.nonceGen();
const { key, ciphertext, authTag } = aes256gcm.encrypt({ data, nonce });
const decrypted = aes256gcm.decrypt({ key, nonce, ciphertext, authTag });
```

##### provide data, key and nonce
```js
import { aes256gcm } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const key = aes256gcm.keyGen();
const nonce = aes256gcm.nonceGen();
const { ciphertext, authTag } = aes256gcm.encrypt({ data, key, nonce });
const decrypted = aes256gcm.decrypt({ key, nonce, ciphertext, authTag });
```

##### provide all including additional data (associated data)
```js
import { aes256gcm } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const key = aes256gcm.keyGen();
const nonce = aes256gcm.nonceGen();
const additionData = Buffer.from('Additional data that is taken into account when generating the MAC.', 'utf8');
const { ciphertext, authTag } = aes256gcm.encrypt({ data, key, nonce, additionalData });

// also fails, if additionalData is not like it was given to encrypt function
const decrypted = aes256gcm.decrypt({ key, nonce, ciphertext, authTag, additionalData });
```

### Inputs/Outputs

#### Buffer
nodejs Buffer with various lengths

#### EncryptionInput (typescript notation, `?` means optional)
* `data`: Buffer
* `key`?: Buffer
* `nonce`?: Buffer
* `additionalData`?: Buffer

#### EncryptionOutput (typescript notation)
* `key`: Buffer
* `nonce`: Buffer
* `ciphertext`: Buffer
* `authTag`: Buffer

#### DecryptionInput (typescript notation, `?` means optional)
* `key`: Buffer
* `nonce`: Buffer
* `ciphertext`: Buffer
* `authTag`: Buffer
* `additionalData`?: Buffer

___

## Used crypto libraries
This package uses the following libraries for it's cryptography:

### `node-crypto`
nodejs provides a native crypto lib. Fast, secure, with great reputation.

### `@stablelib/xchacha20`
`@stablelib/xchacha20` provides ready to use xchacha20, but we only use hchacha from it,
which is required to build xchacha20-poly1305 upon `node-crypto`'s chacha20-poly1305. \
`@stablelib/xchacha20`'s hchacha implementation works and it is hard (if not imposiible) to implement hchacha **working but insecure** and therefore it seems viable to use.

___

## Further readings
* nodejs crypto api: https://nodejs.org/api/crypto.html
* AEAD: https://en.wikipedia.org/wiki/Authenticated_encryption
* AES: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
* GCM: https://en.wikipedia.org/wiki/Galois/Counter_Mode
* CCM: https://en.wikipedia.org/wiki/CCM_mode
* CTR: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
* HMAC: https://en.wikipedia.org/wiki/HMAC
* SHA256: https://en.wikipedia.org/wiki/SHA-2
* chacha20-poly1305: https://en.wikipedia.org/wiki/ChaCha20-Poly1305
* xchacha20: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20

## Development

### install dependencies
```sh
npm install
```

### QA
```shell
npm run qa
```

### License Check
(reports `scss-parser` to be incompatible, which is a scss-parser bug, due to invalid License declaration)
```shell
npm run licenseCheck
```

### Only Tests
```shell
npm run test
```

### Build
```shell
npm run build
```

### Release Package on npm
`[this should be done by github actions]`

___

## License
This project is MIT License \
See [LICENSE.txt](./LICENSE.txt)

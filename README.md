# buffer-aead

Buffer encryption, using aead (authenticated encryption with associated data), powered by strong crypto algorithms, written in typescrypt

## install
```shell
npm i buffer-aead
```

## Supported aead algorithms/suites
* AES-256-CTR & HMAC (not recommended)
* AES-256-GCM (default)
* XChaCha20-Poly1305

## Usage

Quick example (AES-256-GCM):
```js
const { key, nonce, ciphertext, authTag } = encrypt({ data });
const decrypted = decrypt({ key, nonce, ciphertext, authTag });
```

### encrypt and decrypt
`buffer-aead` package provides 2 main functions:
* `encrypt`
  * takes a `EncryptionInput` object
  * returns a `EncryptionOutput` object
* `decrypt`
  * takes a `DecryptionInput` object
  * returns a `Buffer`

See [Inputs/Outputs](#inputsoutputs) for details.

#### Examples

##### default aead (AES-256-GCM), automatic generated key and nonce, no additional associated data
```js
import { encrypt, decrypt } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const { key, nonce, ciphertext, authTag } = encrypt({ data });
const decrypted = decrypt({ key, nonce, ciphertext, authTag });
```

##### default aead (AES-256-GCM), automatic generated nonce, no additional associated data
```js
import { encrypt, decrypt } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const key = Buffer.from('some key, better generate random', 'utf8'); // better use keyGen function
const { nonce, ciphertext, authTag } = encrypt({ data, key });
const decrypted = decrypt({ key, nonce, ciphertext, authTag });
```

##### default aead (AES-256-GCM), automatic generated key, no additional associated data
```js
import { encrypt, decrypt } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const nonce = Buffer.from('string nonce', 'utf8'); // better use nonceGen function
const { key, ciphertext, authTag } = encrypt({ data, nonce });
const decrypted = decrypt({ key, nonce, ciphertext, authTag });
```

##### default aead (AES-256-GCM), no additional associated data
```js
import { encrypt, decrypt } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const key = Buffer.from('some key, better generate random', 'utf8'); // better use keyGen function
const nonce = Buffer.from('string nonce', 'utf8'); // better use nonceGen function
const { ciphertext, authTag } = encrypt({ data, key, nonce });
const decrypted = decrypt({ key, nonce, ciphertext, authTag });
```

##### default aead (AES-256-GCM), with additional associated data
```js
import { encrypt, decrypt } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const key = Buffer.from('some key, better generate random', 'utf8'); // better use keyGen function
const nonce = Buffer.from('string nonce', 'utf8'); // better use nonceGen function
const additionalData = Buffer.from('some additional Data, some file name for example', 'utf8');
const { ciphertext, authTag } = encrypt({ data, key, nonce, additionalData });
const decrypted = decrypt({ key, nonce, ciphertext, authTag, additionalData });
```

##### AES-256-CTR-HMAC, automatic generated key and nonce, no additional associated data
```js
import { encrypt, decrypt } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const { key, nonce, ciphertext, authTag } = encrypt({ data, aead: 'aesctrhmac' });
const decrypted = decrypt({ key, nonce, ciphertext, authTag, aead: 'aesctrhmac' });
```

##### XChaCha20Poly1305, automatic generated key and nonce, no additional associated data
```js
import { encrypt, decrypt } from 'buffer-aead';
const data = Buffer.from('example buffer to encrypt', 'utf8');
const { key, nonce, ciphertext, authTag } = encrypt({ data, aead: 'xchacha20poly1305' });
const decrypted = decrypt({ key, nonce, ciphertext, authTag, aead: 'xchacha20poly1305' });
```

### key/nonce generation
To simplify key/nonce generation, force correct length and prevent miss-use, there are two helper functions:
* `keyGen`
  * optionally takes an aead specifying string (`AEAD`)
  * returns key `Buffer`, suitable for given aead (or for AES-256-GCM as default)
* `nonceGen`
  * optionally takes an aead specifying string (`AEAD`)
  * returns nonce `Buffer`, suitable for given aead (or for AES-256-GCM as default)

See [Inputs/Outputs](#inputsoutputs) for details.

#### Examples

##### generate key and nonce for default aead (AES-256-GCM)
```js
import { keyGen, nonceGen } from 'buffer-aead';
const key = keyGen();
const nonce = nonceGen();
```

##### generate key and nonce for AES-256-CTR-HMAC
```js
import { keyGen, nonceGen } from 'buffer-aead';
const key = keyGen('aesctrhmac');
const nonce = nonceGen('aesctrhmac');
```

##### generate key and nonce for XChaCha20Poly1305
```js
import { keyGen, nonceGen } from 'buffer-aead';
const key = keyGen('xchacha20poy1305');
const nonce = nonceGen('xchacha20poy1305');
```

## Inputs/Outputs

### AEAD
string (`'aesgcm'`, `'aesctrhmac'` or `'xchacha20poly1305'`)

### EncryptionInput
* `data`: Buffer
* `key`: Buffer (optional)
* `nonce`: Buffer (optional)
* `additionalData`: Buffer (optional)
* `aead`: AEAD (optional)

### EncryptionOutput
* `ciphertext`: Buffer
* `authTag`: Buffer
* `key`: Buffer
* `nonce`: Buffer
* `additionalData`: Buffer or null
* `aead`: AEAD

### DecryptionInput
* `ciphertext`: Buffer
* `authTag`: Buffer
* `key`: Buffer
* `nonce`: Buffer
* `additionalData`: Buffer (optional)
* `aead`: AEAD (optional)

## Development

### install dependencies
```sh
npm install
```

### QA

* including licenseCheck (reports `scss-parser` to be incompatible, which is a scss-parser bug)
  ```shell
  npx roboter qa
  ```
* excluding licenseCheck
  ```shell
  npx roboter analyze && npx roboter test && npx roboter deps
  ```
* only tests
  ```shell
  npx roboter test
  ```
* build
  ```shell
  npx roboter build
  ```
* release package \
  `[this should be done by github actions]`

## License
This project is MIT License \
See [LICENSE.txt](./LICENSE.txt)

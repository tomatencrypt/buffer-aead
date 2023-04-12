import Aead from '../types/Aead';
import crypto from 'crypto';
import DecryptionInput from '../types/DecryptionInput';
import EncryptionInput from '../types/EncryptionInput';
import EncryptionOutput from '../types/EncryptionOutput';

interface HmacSignInput {
  ciphertext: Buffer;
  key: Buffer;
  nonce: Buffer;
  additionalData: Buffer;
}

interface HmacVerifyInput extends HmacSignInput {
  mac: Buffer;
}

const algorithm = 'aes-256-ctr';
const hashFunction = 'sha-256';

const hmacSign = ({ ciphertext, key, nonce, additionalData }: HmacSignInput): Buffer => {
  const hmac = crypto.createHmac(hashFunction, key);
  hmac.update(ciphertext);
  hmac.update(nonce);
  hmac.update(additionalData);
  return hmac.digest();
};

const hmacVerify = ({ ciphertext, key, nonce, additionalData, mac }: HmacVerifyInput): void => {
  const actualMac = hmacSign({ ciphertext, key, nonce, additionalData });
  if (!mac.equals(actualMac)) {
    throw new Error('Unsupported state or unable to authenticate data');
  }
};

const keyGen = (): Buffer => crypto.randomBytes(64);
const nonceGen = (): Buffer => crypto.randomBytes(16);

const encrypt = (input: EncryptionInput): EncryptionOutput => {
  const key = input.key ?? keyGen();
  const nonce = input.nonce ?? nonceGen();
  const additionalData = input.additionalData ?? Buffer.alloc(0);

  const encrypter = crypto.createCipheriv(algorithm, key.subarray(0, 32), nonce);

  const ciphertext = Buffer.concat([ encrypter.update(input.data), encrypter.final() ]);
  const authTag = hmacSign({ ciphertext, key: key.subarray(32, 64), nonce, additionalData });

  return { key, nonce, ciphertext, authTag };
};

const decrypt = (input: DecryptionInput): Buffer => {
  const { ciphertext, authTag, key, nonce } = input;
  const additionalData = input.additionalData ?? Buffer.alloc(0);

  hmacVerify({ ciphertext, key: key.subarray(32, 64), nonce, additionalData, mac: authTag });

  const decrypter = crypto.createDecipheriv(algorithm, key.subarray(0, 32), nonce);

  return Buffer.concat([ decrypter.update(ciphertext), decrypter.final() ]);
};

const aesgcm: Aead = { keyGen, nonceGen, encrypt, decrypt };

export default aesgcm;

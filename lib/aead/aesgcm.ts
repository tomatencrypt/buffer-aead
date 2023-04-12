import Aead from '../types/Aead';
import crypto from 'crypto';
import DecryptionInput from '../types/DecryptionInput';
import EncryptionInput from '../types/EncryptionInput';
import EncryptionOutput from '../types/EncryptionOutput';

const algorithm = 'aes-256-gcm';

const keyGen = (): Buffer => crypto.randomBytes(32);
const nonceGen = (): Buffer => crypto.randomBytes(12);

const encrypt = (input: EncryptionInput): EncryptionOutput => {
  const key = input.key ?? keyGen();
  const nonce = input.nonce ?? nonceGen();
  const additionalData = input.additionalData ?? Buffer.alloc(0);

  const encrypter = crypto.createCipheriv(algorithm, key, nonce);
  encrypter.setAAD(additionalData);

  const ciphertext = Buffer.concat([ encrypter.update(input.data), encrypter.final() ]);
  const authTag = encrypter.getAuthTag();

  return { key, nonce, ciphertext, authTag };
};

const decrypt = (input: DecryptionInput): Buffer => {
  const { ciphertext, authTag, key, nonce } = input;
  const additionalData = input.additionalData ?? Buffer.alloc(0);

  const decrypter = crypto.createDecipheriv(algorithm, key, nonce);
  decrypter.setAAD(additionalData);
  decrypter.setAuthTag(authTag);

  return Buffer.concat([ decrypter.update(ciphertext), decrypter.final() ]);
};

const aesgcm: Aead = { keyGen, nonceGen, encrypt, decrypt };

export default aesgcm;

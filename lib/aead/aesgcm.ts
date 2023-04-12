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

  const cipher = crypto.createCipheriv(algorithm, key, nonce);
  cipher.setAAD(additionalData);

  const ciphertext = Buffer.concat([ cipher.update(input.data), cipher.final() ]);
  const authTag = cipher.getAuthTag();

  return { key, nonce, ciphertext, authTag };
};

const decrypt = (input: DecryptionInput): Buffer => {
  const { ciphertext, authTag, key, nonce } = input;
  const additionalData = input.additionalData ?? Buffer.alloc(0);

  const decipher = crypto.createDecipheriv(algorithm, key, nonce);
  decipher.setAAD(additionalData);
  decipher.setAuthTag(authTag);

  return Buffer.concat([ decipher.update(ciphertext), decipher.final() ]);
};

const aesgcm: Aead = { keyGen, nonceGen, encrypt, decrypt };

export default aesgcm;

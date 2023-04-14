import AbstractBufferAead from './AbstractBufferAead';
import BufferAeadType from '../types/BufferAeadType';
import crypto from 'crypto';
import DecryptionInput from '../types/DecryptionInput';
import EncryptionInput from '../types/EncryptionInput';
import EncryptionOutput from '../types/EncryptionOutput';

abstract class AbstractBufferAeadGcm extends AbstractBufferAead {
  private readonly algorithm: BufferAeadType;

  public constructor (algorithm: BufferAeadType) {
    // eslint-disable-next-line prefer-named-capture-group
    const keyLength = Number.parseInt(algorithm.replace(/^aes-(128|192|256)-gcm$/u, '$1'), 10) / 8;
    const nonceLength = 12;

    super({ keyLength, nonceLength });
    this.algorithm = algorithm;
  }

  public encrypt (input: EncryptionInput): EncryptionOutput {
    const key = input.key ?? this.keyGen();
    const nonce = input.nonce ?? this.nonceGen();
    const additionalData = input.additionalData ?? Buffer.alloc(0);

    const encrypter = crypto.createCipheriv(this.algorithm, key, nonce) as crypto.CipherGCM;
    encrypter.setAAD(additionalData);

    const ciphertext = Buffer.concat([ encrypter.update(input.data), encrypter.final() ]);
    const authTag = encrypter.getAuthTag();

    return { key, nonce, ciphertext, authTag };
  }

  public decrypt (input: DecryptionInput): Buffer {
    const { ciphertext, authTag, key, nonce } = input;
    const additionalData = input.additionalData ?? Buffer.alloc(0);

    const decrypter = crypto.createDecipheriv(this.algorithm, key, nonce) as crypto.DecipherGCM;
    decrypter.setAAD(additionalData);
    decrypter.setAuthTag(authTag);

    try {
      return Buffer.concat([ decrypter.update(ciphertext), decrypter.final() ]);
    } catch (ex: unknown) {
      const errMsg = ex ? (ex as Error).message : '';
      if (errMsg === 'Unsupported state or unable to authenticate data') {
        throw new Error('Unauthentic data');
      } else {
        throw ex;
      }
    }
  }
}

export default AbstractBufferAeadGcm;

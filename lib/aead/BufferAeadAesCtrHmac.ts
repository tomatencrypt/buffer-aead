import AbstractBufferAead from './AbstractBufferAead';
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

class BufferAeadAesCtrHmac extends AbstractBufferAead {
  private readonly algorithm = 'aes-256-ctr';

  private readonly hashFunction = 'sha256';

  public constructor () {
    super({ keyLength: 64, nonceLength: 16 });
  }

  public encrypt (input: EncryptionInput): EncryptionOutput {
    const key = input.key ?? this.keyGen();
    const nonce = input.nonce ?? this.nonceGen();
    const additionalData = input.additionalData ?? Buffer.alloc(0);

    const encrypter = crypto.createCipheriv(this.algorithm, key.subarray(0, 32), nonce);

    const ciphertext = Buffer.concat([ encrypter.update(input.data), encrypter.final() ]);
    const authTag = this.hmacSign({ ciphertext, key: key.subarray(32, 64), nonce, additionalData });

    return { key, nonce, ciphertext, authTag };
  }

  public decrypt (input: DecryptionInput): Buffer {
    const { ciphertext, authTag, key, nonce } = input;
    const additionalData = input.additionalData ?? Buffer.alloc(0);

    this.hmacVerify({ ciphertext, key: key.subarray(32, 64), nonce, additionalData, mac: authTag });

    const decrypter = crypto.createDecipheriv(this.algorithm, key.subarray(0, 32), nonce);

    return Buffer.concat([ decrypter.update(ciphertext), decrypter.final() ]);
  }

  private hmacSign ({ ciphertext, key, nonce, additionalData }: HmacSignInput): Buffer {
    const hmac = crypto.createHmac(this.hashFunction, key);
    hmac.update(ciphertext);
    hmac.update(nonce);
    hmac.update(additionalData);
    return hmac.digest();
  }

  private hmacVerify ({ ciphertext, key, nonce, additionalData, mac }: HmacVerifyInput): void {
    const actualMac = this.hmacSign({ ciphertext, key, nonce, additionalData });
    if (!mac.equals(actualMac)) {
      throw new Error('Unauthentic data');
    }
  }
}

export default BufferAeadAesCtrHmac;

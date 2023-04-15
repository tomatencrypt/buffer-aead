import BufferAead from '../types/BufferAead';
import crypto from 'crypto';
import DecryptionInput from '../types/DecryptionInput';
import EncryptionInput from '../types/EncryptionInput';
import EncryptionOutput from '../types/EncryptionOutput';

abstract class AbstractBufferAead implements BufferAead {
  private readonly keyLength: number;

  private readonly nonceLength: number;

  public constructor ({ keyLength, nonceLength }: { keyLength: number; nonceLength: number }) {
    this.keyLength = keyLength;
    this.nonceLength = nonceLength;
  }

  public keyGen (): Buffer {
    return crypto.randomBytes(this.keyLength);
  }

  public nonceGen (): Buffer {
    return crypto.randomBytes(this.nonceLength);
  }

  public abstract encrypt (input: EncryptionInput): EncryptionOutput;

  public abstract decrypt (input: DecryptionInput): Buffer;

  protected static decryptIfAuthentic (decrypter: crypto.DecipherCCM | crypto.DecipherGCM, ciphertext: Buffer): Buffer {
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

export default AbstractBufferAead;

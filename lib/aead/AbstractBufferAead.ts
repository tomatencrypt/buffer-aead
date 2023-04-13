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
}

export default AbstractBufferAead;

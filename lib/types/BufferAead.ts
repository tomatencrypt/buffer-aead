import DecryptionInput from './DecryptionInput';
import EncryptionInput from './EncryptionInput';
import EncryptionOutput from './EncryptionOutput';

interface BufferAead {
  keyGen: () => Buffer;
  nonceGen: () => Buffer;
  encrypt: (input: EncryptionInput) => EncryptionOutput;
  decrypt: (input: DecryptionInput) => Buffer;
}

export default BufferAead;

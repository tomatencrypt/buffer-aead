import DecryptionInput from './DecryptionInput';
import EncryptionInput from './EncryptionInput';
import EncryptionOutput from './EncryptionOutput';

interface Aead {
  encrypt: (input: EncryptionInput) => EncryptionOutput;
  decrypt: (input: DecryptionInput) => Buffer;
  keyGen: () => Buffer;
  nonceGen: () => Buffer;
}

export default Aead;

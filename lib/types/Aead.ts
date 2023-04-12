import AeadSpecifier from './AeadSpecifier';
import DecryptionInput from './DecryptionInput';
import EncryptionInput from './EncryptionInput';
import EncryptionOutput from './EncryptionOutput';

interface Aead {
  keyGen: (aead?: AeadSpecifier) => Buffer;
  nonceGen: (aead?: AeadSpecifier) => Buffer;
  encrypt: (input: EncryptionInput) => EncryptionOutput;
  decrypt: (input: DecryptionInput) => Buffer;
}

export default Aead;

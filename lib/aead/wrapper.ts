import Aead from '../types/Aead';
import AeadSpecifier from 'lib/types/AeadSpecifier';
import aesgcm from './aesgcm';
import DecryptionInput from '../types/DecryptionInput';
import EncryptionInput from '../types/EncryptionInput';
import EncryptionOutput from '../types/EncryptionOutput';

const defaultAead = 'aesgcm';

const aeads: Record<AeadSpecifier, Aead> = {
  aesgcm,

  // TODO [2023-04-30]: use aesctrhmac instead
  aesctrhmac: aesgcm,

  // TODO [2023-04-30]: use xchacha20poly1305 instead
  xchacha20poly1305: aesgcm
};

const keyGen = (aead: AeadSpecifier = defaultAead): Buffer => aeads[aead].keyGen();
const nonceGen = (aead: AeadSpecifier = defaultAead): Buffer => aeads[aead].nonceGen();

const encrypt = (input: EncryptionInput): EncryptionOutput => {
  const aead = input.aead ?? defaultAead;
  return aeads[aead].encrypt(input);
};

const decrypt = (input: DecryptionInput): Buffer => {
  const aead = input.aead ?? defaultAead;
  return aeads[aead].decrypt(input);
};

const wrapper: Aead = { keyGen, nonceGen, encrypt, decrypt };

export { wrapper, aeads, defaultAead };

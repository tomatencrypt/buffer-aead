import AeadSpecifier from './AeadSpecifier';

export default interface DecryptionInput {
  key: Buffer;
  nonce: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
  additionalData?: Buffer;
  aead?: AeadSpecifier;
}

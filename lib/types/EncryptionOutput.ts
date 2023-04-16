export default interface EncryptionOutput {
  key: Buffer;
  nonce: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
}

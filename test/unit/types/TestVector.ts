export default interface TestVector {
  data: Buffer;
  key: Buffer;
  nonce: Buffer;
  additionalData: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
}

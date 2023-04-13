export default interface EncryptionInput {
  data: Buffer;
  key?: Buffer;
  nonce?: Buffer;
  additionalData?: Buffer;
}

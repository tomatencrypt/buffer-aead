const aesCtrHmacTestVector = {
  // Official test vector from https://datatracker.ietf.org/doc/html/rfc3686.html#page-9
  // Test Vector #7
  key: Buffer.from('776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104', 'hex'),
  nonce: Buffer.from('00000060DB5672C97AA8F0B200000001', 'hex'),
  data: Buffer.from('53696E676C6520626C6F636B206D7367', 'hex'),
  ciphertext: Buffer.from('145AD01DBF824EC7560863DC71E3E0C0', 'hex'),

  // Defined additionalData and tested authTag manually, before it was hard coded here
  additionalData: Buffer.from('010203', 'hex'),
  authTag: Buffer.from('5E788FDB1290D3E4872BAE4BE3921D77D4E1AD72AEF06525649E10D7A8C03F90', 'hex')
};

export default aesCtrHmacTestVector;

const aes192gcmTestVector = {
  // Official test vector from https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
  // Section B; Test Case 10
  key: Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c', 'hex'),
  nonce: Buffer.from('cafebabefacedbaddecaf888', 'hex'),
  data: Buffer.from(
    'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    'hex'
  ),
  additionalData: Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
  ciphertext: Buffer.from(
    '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710',
    'hex'
  ),
  authTag: Buffer.from('2519498e80f1478f37ba55bd6d27618c', 'hex')
};

export default aes192gcmTestVector;

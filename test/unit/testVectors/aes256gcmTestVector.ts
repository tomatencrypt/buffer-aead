// Official test vector from https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
// Section B; Test Case 16
const aes256gcmTestVector = {
  key: Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex'),
  nonce: Buffer.from('cafebabefacedbaddecaf888', 'hex'),
  data: Buffer.from(
    'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    'hex'
  ),
  additionalData: Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
  ciphertext: Buffer.from(
    '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
    'hex'
  ),
  authTag: Buffer.from('76fc6ece0f4e1768cddf8853bb2d551b', 'hex')
};

export default aes256gcmTestVector;

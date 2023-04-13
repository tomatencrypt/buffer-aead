// Official test vector from https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
// Section B; Test Case 4
const aes128gcmTestVector = {
  key: Buffer.from('feffe9928665731c6d6a8f9467308308', 'hex'),
  nonce: Buffer.from('cafebabefacedbaddecaf888', 'hex'),
  data: Buffer.from(
    'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    'hex'
  ),
  additionalData: Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
  ciphertext: Buffer.from(
    '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
    'hex'
  ),
  authTag: Buffer.from('5bc94fbc3221a5db94fae95ae7121a47', 'hex')
};

export default aes128gcmTestVector;

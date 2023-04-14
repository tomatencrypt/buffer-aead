// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
// unzipped/VPT128.rsp; test 240 (lines 1332 .. 1338)
const aes128ccmTestVector = {
  key: Buffer.from('43c1142877d9f450e12d7b6db47a85ba', 'hex'),
  nonce: Buffer.from('76becd9d27ca8a026215f32712', 'hex'),
  data: Buffer.from('b506a6ba900c1147c806775324b36eb376aa01d4c3eef6f5', 'hex'),
  additionalData: Buffer.from('6a59aacadd416e465264c15e1a1e9bfa084687492710f9bda832e2571e468224', 'hex'),

  // We splitted ciphertext and authTag
  ciphertext: Buffer.from('14b14fe5b317411392861638ec383ae40ba95fefe34255dc', 'hex'),
  authTag: Buffer.from('2ec067887114bc370281de6f00836ce4', 'hex')
};

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
// unzipped/VPT192.rsp; test 240 (lines 1332 .. 1338)
const aes192ccmTestVector = {
  key: Buffer.from('91f9d636a071c3aad1743137e0644a73de9e47bd76acd919', 'hex'),
  nonce: Buffer.from('1bf491ac320d660eb2dd45c6c3', 'hex'),
  data: Buffer.from('4eaf9384cad976f65f98042d561d760b5a787330dc658f6c', 'hex'),
  additionalData: Buffer.from('3bdfd7f18d2b6d0804d779f0679aaa2d7d32978c2df8015ae4b758d337be81dd', 'hex'),

  // We splitted ciphertext and authTag
  ciphertext: Buffer.from('635530cab14e3d0a135bb6eebb5829412676e6dd4995f99c', 'hex'),
  authTag: Buffer.from('b7e17f235bd660e7e17b2c65320e9fd4', 'hex')
};

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
// unzipped/VPT256.rsp; test 240 (lines 1332 .. 1338)
const aes256ccmTestVector = {
  key: Buffer.from('4ad98dbef0fb2a188b6c49a859c920967214b998435a00b93d931b5acecaf976', 'hex'),
  nonce: Buffer.from('00d772b07788536b688ff2b84a', 'hex'),
  data: Buffer.from('9cea3b061e5c402d48497ea4948d75b8af7746d4e570c848', 'hex'),
  additionalData: Buffer.from('5f8b1400920891e8057639618183c9c847821c1aae79f2a90d75f114db21e975', 'hex'),

  // We splitted ciphertext and authTag
  ciphertext: Buffer.from('f28ec535c2d834963c85814ec4173c0b8983dff8dc4a2d4e', 'hex'),
  authTag: Buffer.from('0f73bfb28ad42aa8f75f549a93594dd4', 'hex')
};

// https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
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

// https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
// Section B; Test Case 10
const aes192gcmTestVector = {
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

// https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
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

// Test vector for aes-256-ctr from https://datatracker.ietf.org/doc/html/rfc3686.html#page-9
// Test Vector #7
const aesCtrHmacTestVector = {
  key: Buffer.from('776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104', 'hex'),

  // Counter Block (1), Nonce notation is wrong
  nonce: Buffer.from('00000060DB5672C97AA8F0B200000001', 'hex'),

  data: Buffer.from('53696E676C6520626C6F636B206D7367', 'hex'),
  ciphertext: Buffer.from('145AD01DBF824EC7560863DC71E3E0C0', 'hex'),

  // Not part of the official vector. Defined additionalData and tested authTag manually, before it was hard coded here
  // tested here: https://www.liavaag.org/English/SHA-Generator/HMAC/
  additionalData: Buffer.from('010203', 'hex'),
  authTag: Buffer.from('5E788FDB1290D3E4872BAE4BE3921D77D4E1AD72AEF06525649E10D7A8C03F90', 'hex')
};

// Official test vector from https://datatracker.ietf.org/doc/html/draft-nir-cfrg-chacha20-poly1305#appendix-A.5
const chacha20poly1305TestVector = {
  key: Buffer.from('1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0', 'hex'),
  nonce: Buffer.from('000000000102030405060708', 'hex'),
  data: Buffer.from(
    '496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e7468' +
    '7320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e74732061742061' +
    '6e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174' +
    '657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d',
    'hex'
  ),
  additionalData: Buffer.from('f33388860000000000004e91', 'hex'),
  ciphertext: Buffer.from(
    '64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e' +
    '710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46' +
    'a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd6' +
    '3159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b',
    'hex'
  ),
  authTag: Buffer.from('eead9d67890cbb22392336fea1851f38', 'hex')
};

export {
  aes128ccmTestVector, aes128gcmTestVector,
  aes192ccmTestVector, aes192gcmTestVector,
  aes256ccmTestVector, aes256gcmTestVector,
  aesCtrHmacTestVector,
  chacha20poly1305TestVector
};

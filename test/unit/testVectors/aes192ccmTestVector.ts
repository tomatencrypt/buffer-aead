// Official test vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
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

export default aes192ccmTestVector;

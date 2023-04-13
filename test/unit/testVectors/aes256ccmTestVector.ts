// Official test vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
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

export default aes256ccmTestVector;

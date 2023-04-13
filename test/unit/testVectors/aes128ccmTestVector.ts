// Official test vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
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

export default aes128ccmTestVector;

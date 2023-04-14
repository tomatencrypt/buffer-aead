import AbstractBufferAeadAesCcm from './AbstractBufferAeadCcm';

class BufferAeadAes128Ccm extends AbstractBufferAeadAesCcm {
  public constructor () {
    super({ algorithm: 'aes-128-ccm', keyLength: 16, nonceLength: 13 });
  }
}

export default BufferAeadAes128Ccm;

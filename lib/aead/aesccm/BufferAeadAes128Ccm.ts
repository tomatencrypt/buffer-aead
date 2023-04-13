import AbstractBufferAeadAesCcm from './AbstractBufferAeadAesCcm';

class BufferAeadAes128Ccm extends AbstractBufferAeadAesCcm {
  public constructor () {
    super('aes-128-ccm');
  }
}

export default BufferAeadAes128Ccm;

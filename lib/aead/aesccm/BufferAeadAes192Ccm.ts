import AbstractBufferAeadAesCcm from './AbstractBufferAeadAesCcm';

class BufferAeadAes192Ccm extends AbstractBufferAeadAesCcm {
  public constructor () {
    super('aes-192-ccm');
  }
}

export default BufferAeadAes192Ccm;

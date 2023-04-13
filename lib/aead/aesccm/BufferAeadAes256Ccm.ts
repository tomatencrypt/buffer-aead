import AbstractBufferAeadAesCcm from './AbstractBufferAeadAesCcm';

class BufferAeadAes256Ccm extends AbstractBufferAeadAesCcm {
  public constructor () {
    super('aes-256-ccm');
  }
}

export default BufferAeadAes256Ccm;

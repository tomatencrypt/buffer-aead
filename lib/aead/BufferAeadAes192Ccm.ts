import AbstractBufferAeadAesCcm from './AbstractBufferAeadCcm';

class BufferAeadAes192Ccm extends AbstractBufferAeadAesCcm {
  public constructor () {
    super({ algorithm: 'aes-192-ccm', keyLength: 24, nonceLength: 13 });
  }
}

export default BufferAeadAes192Ccm;

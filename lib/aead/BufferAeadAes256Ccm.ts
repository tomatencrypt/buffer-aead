import AbstractBufferAeadAesCcm from './AbstractBufferAeadCcm';

class BufferAeadAes256Ccm extends AbstractBufferAeadAesCcm {
  public constructor () {
    super({ algorithm: 'aes-256-ccm', keyLength: 32, nonceLength: 13 });
  }
}

export default BufferAeadAes256Ccm;

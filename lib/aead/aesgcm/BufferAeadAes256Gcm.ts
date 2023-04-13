import AbstractBufferAeadAesGcm from './AbstractBufferAeadAesGcm';

class BufferAeadAes256Gcm extends AbstractBufferAeadAesGcm {
  public constructor () {
    super('aes-256-gcm');
  }
}

export default BufferAeadAes256Gcm;

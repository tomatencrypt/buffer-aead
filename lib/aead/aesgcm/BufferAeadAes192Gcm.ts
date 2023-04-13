import AbstractBufferAeadAesGcm from './AbstractBufferAeadAesGcm';

class BufferAeadAes192Gcm extends AbstractBufferAeadAesGcm {
  public constructor () {
    super('aes-192-gcm');
  }
}

export default BufferAeadAes192Gcm;

import AbstractBufferAeadAesGcm from './AbstractBufferAeadAesGcm';

class BufferAeadAes128Gcm extends AbstractBufferAeadAesGcm {
  public constructor () {
    super('aes-128-gcm');
  }
}

export default BufferAeadAes128Gcm;

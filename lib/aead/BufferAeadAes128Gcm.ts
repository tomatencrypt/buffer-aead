import AbstractBufferAeadAesGcm from './AbstractBufferAeadGcm';

class BufferAeadAes128Gcm extends AbstractBufferAeadAesGcm {
  public constructor () {
    super({ algorithm: 'aes-128-gcm', keyLength: 16, nonceLength: 12 });
  }
}

export default BufferAeadAes128Gcm;

import AbstractBufferAeadAesGcm from './AbstractBufferAeadGcm';

class BufferAeadAes192Gcm extends AbstractBufferAeadAesGcm {
  public constructor () {
    super({ algorithm: 'aes-192-gcm', keyLength: 24, nonceLength: 12 });
  }
}

export default BufferAeadAes192Gcm;

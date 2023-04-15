import AbstractBufferAeadAesGcm from './AbstractBufferAeadGcm';

class BufferAeadAes256Gcm extends AbstractBufferAeadAesGcm {
  public constructor () {
    super({ algorithm: 'aes-256-gcm', keyLength: 32, nonceLength: 12 });
  }
}

export default BufferAeadAes256Gcm;

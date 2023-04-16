import AbstractBufferAeadAesCcm from './AbstractBufferAeadCcm';

class BufferAeadChacha20Poly1305 extends AbstractBufferAeadAesCcm {
  public constructor () {
    super({ algorithm: 'chacha20-poly1305', keyLength: 32, nonceLength: 12 });
  }
}

export default BufferAeadChacha20Poly1305;

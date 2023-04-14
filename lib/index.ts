import BufferAeadAes128Ccm from './aead/BufferAeadAes128Ccm';
import BufferAeadAes128Gcm from './aead/BufferAeadAes128Gcm';
import BufferAeadAes192Ccm from './aead/BufferAeadAes192Ccm';
import BufferAeadAes192Gcm from './aead/BufferAeadAes192Gcm';
import BufferAeadAes256Ccm from './aead/BufferAeadAes256Ccm';
import BufferAeadAes256Gcm from './aead/BufferAeadAes256Gcm';
import BufferAeadAesCtrHmac from './aead/BufferAeadAesCtrHmac';
import BufferAeadChacha20Poly1305 from './aead/BufferAeadChacha20Poly1305';
import BufferAeadXchacha20Poly1305 from './aead/BufferAeadXchacha20Poly1305';

const aes128ccm = new BufferAeadAes128Ccm();
const aes128gcm = new BufferAeadAes128Gcm();

const aes192ccm = new BufferAeadAes192Ccm();
const aes192gcm = new BufferAeadAes192Gcm();

const aes256ccm = new BufferAeadAes256Ccm();
const aes256gcm = new BufferAeadAes256Gcm();

const aesctrhmac = new BufferAeadAesCtrHmac();

const chacha20poly1305 = new BufferAeadChacha20Poly1305();
const xchacha20poly1305 = new BufferAeadXchacha20Poly1305();

export {
  aes128ccm, aes128gcm,
  aes192ccm, aes192gcm,
  aes256ccm, aes256gcm,
  aesctrhmac,
  chacha20poly1305, xchacha20poly1305
};

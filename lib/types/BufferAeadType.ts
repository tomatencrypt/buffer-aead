import crypto from 'crypto';

type BufferAeadType = crypto.CipherGCMTypes | Exclude<crypto.CipherCCMTypes, 'chacha20-poly1305'> | 'aes-ctrhmac' | 'xchacha20-poly1305';

export default BufferAeadType;

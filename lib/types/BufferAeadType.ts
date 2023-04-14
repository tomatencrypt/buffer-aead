import crypto from 'crypto';

type BufferAeadType = crypto.CipherGCMTypes | crypto.CipherCCMTypes | 'aes-ctrhmac' | 'xchacha20-poly1305';

export default BufferAeadType;

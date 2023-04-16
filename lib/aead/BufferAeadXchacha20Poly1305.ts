import AbstractBufferAeadAesCcm from './AbstractBufferAeadCcm';
import DecryptionInput from 'lib/types/DecryptionInput';
import EncryptionInput from 'lib/types/EncryptionInput';
import EncryptionOutput from 'lib/types/EncryptionOutput';
import { hchacha } from '@stablelib/xchacha20';

interface KeyAndNonce {
  key: Buffer;
  nonce: Buffer;
}

class BufferAeadXchacha20Poly1305 extends AbstractBufferAeadAesCcm {
  public constructor () {
    super({ algorithm: 'chacha20-poly1305', keyLength: 32, nonceLength: 24 });
  }

  public encrypt (input: EncryptionInput): EncryptionOutput {
    const key = input.key ?? this.keyGen();
    const nonce = input.nonce ?? this.nonceGen();
    const { key: tweakedKey, nonce: tweakedNonce } = BufferAeadXchacha20Poly1305.tweakKeyAndNonce({ key, nonce });
    const encryptionOutput = super.encrypt({ ...input, key: tweakedKey, nonce: tweakedNonce });
    return { ...encryptionOutput, key, nonce };
  }

  public decrypt (input: DecryptionInput): Buffer {
    const { key, nonce } = input;
    const { key: tweakedKey, nonce: tweakedNonce } = BufferAeadXchacha20Poly1305.tweakKeyAndNonce({ key, nonce });
    return super.decrypt({ ...input, key: tweakedKey, nonce: tweakedNonce });
  }

  private static tweakKeyAndNonce ({ key, nonce }: KeyAndNonce): KeyAndNonce {
    const hchachaNonce = nonce.subarray(0, 16);
    let tweakedKey = new Uint8Array(32);
    tweakedKey = hchacha(key, hchachaNonce, tweakedKey);
    const tweakedNonce = Buffer.concat([ new Uint8Array(4), nonce.subarray(16, 24) ]);
    return { key: Buffer.from(tweakedKey), nonce: tweakedNonce };
  }
}

export default BufferAeadXchacha20Poly1305;

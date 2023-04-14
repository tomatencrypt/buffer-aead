import { assert } from 'assertthat';
import BufferAeadType from '../../lib/types/BufferAeadType';
import crypto from 'crypto';
import sinon from 'sinon';
import TestDefinition from './types/TestDefinition';
import TestVector from './types/TestVector';
import {
  aes128ccm, aes128gcm,
  aes192ccm, aes192gcm,
  aes256ccm, aes256gcm,
  aesctrhmac,
  chacha20poly1305, xchacha20poly1305
} from '../../lib';
import {
  aes128ccmTestVector, aes128gcmTestVector,
  aes192ccmTestVector, aes192gcmTestVector,
  aes256ccmTestVector, aes256gcmTestVector,
  aesctrhmacTestVector,
  chacha20poly1305TestVector, xchacha20poly1305TestVector
} from './testVectors';

// Flips last bit (least significant bit) of the buffer
const tamperBuffer = (source: Buffer): Buffer => {
  const tampered = Buffer.alloc(source.length);
  source.copy(tampered);

  // eslint-disable-next-line no-bitwise
  tampered[source.length - 1] ^= 1;

  return tampered;
};

const aeadDefinitions: Record<BufferAeadType, TestDefinition> = {
  'aes-128-ccm': {
    aead: aes128ccm,
    testVector: aes128ccmTestVector
  },
  'aes-192-ccm': {
    aead: aes192ccm,
    testVector: aes192ccmTestVector
  },
  'aes-256-ccm': {
    aead: aes256ccm,
    testVector: aes256ccmTestVector
  },
  'aes-128-gcm': {
    aead: aes128gcm,
    testVector: aes128gcmTestVector
  },
  'aes-192-gcm': {
    aead: aes192gcm,
    testVector: aes192gcmTestVector
  },
  'aes-256-gcm': {
    aead: aes256gcm,
    testVector: aes256gcmTestVector
  },
  'aes-ctrhmac': {
    aead: aesctrhmac,
    testVector: aesctrhmacTestVector
  },
  'chacha20-poly1305': {
    aead: chacha20poly1305,
    testVector: chacha20poly1305TestVector
  },
  'xchacha20-poly1305': {
    aead: xchacha20poly1305,
    testVector: xchacha20poly1305TestVector
  }
};

const mockRandom = (testVector: TestVector): void => {
  sinon.restore();
  sinon.replace(crypto, 'randomBytes', (size: number): Buffer => size === testVector.nonce.length ? testVector.nonce : testVector.key);
};

const ensureRealRandom = (): void => {
  sinon.restore();
};

suite('AEADs', (): void => {
  for (const [ aeadName, definition ] of Object.entries(aeadDefinitions)) {
    const { aead, testVector } = definition;

    suite(`AEAD: ${aeadName}`, (): void => {
      suite('generations', (): void => {
        test('returns correct key, using mocked random.', async (): Promise<void> => {
          mockRandom(testVector);

          const generatedKey = aead.keyGen();

          assert.that(generatedKey).is.equalTo(testVector.key);
        });

        test('returns correct nonce, using mocked random.', async (): Promise<void> => {
          mockRandom(testVector);

          const generatedNonce = aead.nonceGen();

          assert.that(generatedNonce).is.equalTo(testVector.nonce);
        });
      });

      suite('encryption, using official test vector', (): void => {
        test('encrypts correctly using official testvector, all values given.', async (): Promise<void> => {
          const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

          const result = aead.encrypt({ data, key, nonce, additionalData });

          assert.that(result.ciphertext).is.equalTo(ciphertext);
          assert.that(result.authTag).is.equalTo(authTag);
        });

        test('encrypts correctly using official testvector, no key given.', async (): Promise<void> => {
          mockRandom(testVector);
          const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

          const result = aead.encrypt({ data, nonce, additionalData });

          assert.that(result.ciphertext).is.equalTo(ciphertext);
          assert.that(result.authTag).is.equalTo(authTag);

          assert.that(result.key).is.equalTo(key);
        });

        test('encrypts correctly using official testvector, no nonce given.', async (): Promise<void> => {
          mockRandom(testVector);
          const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

          const result = aead.encrypt({ data, key, additionalData });

          assert.that(result.ciphertext).is.equalTo(ciphertext);
          assert.that(result.authTag).is.equalTo(authTag);
          assert.that(result.nonce).is.equalTo(nonce);
        });

        test('encrypts correctly using official testvector, no key and nonce given.', async (): Promise<void> => {
          mockRandom(testVector);
          const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

          const result = aead.encrypt({ data, additionalData });

          assert.that(result.ciphertext).is.equalTo(ciphertext);
          assert.that(result.authTag).is.equalTo(authTag);
          assert.that(result.key).is.equalTo(key);
          assert.that(result.nonce).is.equalTo(nonce);
        });
      });

      suite('decryption, using official test vector', (): void => {
        test('decrypts correctly using official testvector.', async (): Promise<void> => {
          const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

          const decrypted = aead.decrypt({ ciphertext, authTag, key, nonce, additionalData });

          assert.that(decrypted).is.equalTo(data);
        });
      });

      suite('encryption and decryption, using random values', (): void => {
        test('encrypts and decrypts back correctly, given: data.', async (): Promise<void> => {
          ensureRealRandom();
          const data = crypto.randomBytes(10);

          const { key, nonce, ciphertext, authTag } = aead.encrypt({ data });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: data, key.', async (): Promise<void> => {
          ensureRealRandom();
          const data = crypto.randomBytes(10);
          const key = crypto.randomBytes(testVector.key.length);

          const { nonce, ciphertext, authTag } = aead.encrypt({ data, key });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: data, nonce.', async (): Promise<void> => {
          ensureRealRandom();
          const data = crypto.randomBytes(10);
          const nonce = crypto.randomBytes(testVector.nonce.length);

          const { key, ciphertext, authTag } = aead.encrypt({ data, nonce });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: data, key, nonce.', async (): Promise<void> => {
          ensureRealRandom();
          const data = crypto.randomBytes(10);
          const key = crypto.randomBytes(testVector.key.length);
          const nonce = crypto.randomBytes(testVector.nonce.length);

          const { ciphertext, authTag } = aead.encrypt({ data, key, nonce });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: all.', async (): Promise<void> => {
          ensureRealRandom();
          const data = crypto.randomBytes(10);
          const key = crypto.randomBytes(testVector.key.length);
          const nonce = crypto.randomBytes(testVector.nonce.length);
          const additionalData = crypto.randomBytes(3);

          const { ciphertext, authTag } = aead.encrypt({ data, key, nonce, additionalData });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag, additionalData });

          assert.that(decrypted).is.equalTo(data);
        });
      });

      suite('authentication failueres', (): void => {
        const expectedErrorText = 'Unauthentic data';

        test('fails to decrypt due invalid ciphertext.', async (): Promise<void> => {
          const { key, nonce, additionalData, ciphertext, authTag } = testVector;
          const tampered = tamperBuffer(ciphertext);

          assert.that((): void => {
            aead.decrypt({ ciphertext: tampered, authTag, key, nonce, additionalData });
          }).is.throwing(expectedErrorText);
        });

        test('fails to decrypt due invalid authTag.', async (): Promise<void> => {
          const { key, nonce, additionalData, ciphertext, authTag } = testVector;
          const tampered = tamperBuffer(authTag);

          assert.that((): void => {
            aead.decrypt({ ciphertext, authTag: tampered, key, nonce, additionalData });
          }).is.throwing(expectedErrorText);
        });

        test('fails to decrypt due invalid additionalData.', async (): Promise<void> => {
          const { key, nonce, additionalData, ciphertext, authTag } = testVector;
          const tampered = tamperBuffer(additionalData);

          assert.that((): void => {
            aead.decrypt({ ciphertext, authTag, key, nonce, additionalData: tampered });
          }).is.throwing(expectedErrorText);
        });

        test('fails to decrypt due invalid key.', async (): Promise<void> => {
          const { key, nonce, additionalData, ciphertext, authTag } = testVector;
          const tampered = tamperBuffer(key);

          assert.that((): void => {
            aead.decrypt({ ciphertext, authTag, key: tampered, nonce, additionalData });
          }).is.throwing(expectedErrorText);
        });

        test('fails to decrypt due invalid nonce.', async (): Promise<void> => {
          const { key, nonce, additionalData, ciphertext, authTag } = testVector;
          const tampered = tamperBuffer(nonce);

          assert.that((): void => {
            aead.decrypt({ ciphertext, authTag, key, nonce: tampered, additionalData });
          }).is.throwing(expectedErrorText);
        });
      });
    });
  }
});

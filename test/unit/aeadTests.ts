import aes128gcmTestVector from './testVectors/aes128gcmTestVector';
import aes192gcmTestVector from './testVectors/aes192gcmTestVector';
import aes256gcmTestVector from './testVectors/aes256gcmTestVector';
import aesCtrHmacTestVector from './testVectors/aesCtrHmacTestVector';
import { assert } from 'assertthat';
import BufferAeadAes128Gcm from '../../lib/aead/aesgcm/BufferAeadAes128Gcm';
import BufferAeadAes192Gcm from '../../lib/aead/aesgcm/BufferAeadAes192Gcm';
import BufferAeadAes256Gcm from '../../lib/aead/aesgcm/BufferAeadAes256Gcm';
import BufferAeadAesCtrHmac from '../../lib/aead/aesctrhmac/BufferAeadAesCtrHmac';
import BufferAeadType from '../../lib/types/BufferAeadType';
import crypto from 'crypto';
import sinon from 'sinon';
import TestDefinition from './types/TestDefinition';
import TestVector from './types/TestVector';

// Flips last bit (least significant bit) of the buffer
const tamperBuffer = (source: Buffer): Buffer => {
  const tampered = Buffer.alloc(source.length);
  source.copy(tampered);

  // eslint-disable-next-line no-bitwise
  tampered[source.length - 1] ^= 1;

  return tampered;
};

const aeadDefinitions: Record<BufferAeadType, TestDefinition> = {
  'aes-128-gcm': {
    aead: new BufferAeadAes128Gcm(),
    testVector: aes128gcmTestVector
  },
  'aes-192-gcm': {
    aead: new BufferAeadAes192Gcm(),
    testVector: aes192gcmTestVector
  },
  'aes-256-gcm': {
    aead: new BufferAeadAes256Gcm(),
    testVector: aes256gcmTestVector
  },
  'aes-ctrhmac': {
    aead: new BufferAeadAesCtrHmac(),
    testVector: aesCtrHmacTestVector
  },

  // TODO [2023-04-30]: replace this with real definitions when implemented
  'aes-128-ccm': {
    aead: new BufferAeadAes256Gcm(),
    testVector: aes256gcmTestVector
  },
  'aes-192-ccm': {
    aead: new BufferAeadAes256Gcm(),
    testVector: aes256gcmTestVector
  },
  'aes-256-ccm': {
    aead: new BufferAeadAes256Gcm(),
    testVector: aes256gcmTestVector
  },
  'xchacha20-poly1305': {
    aead: new BufferAeadAes256Gcm(),
    testVector: aes256gcmTestVector
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
    // TODO [2023-04-30]: remove this when all aeads implemented
    if (!aeadName.endsWith('-gcm') && aeadName !== 'aes-ctrhmac') {
      return;
    }

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

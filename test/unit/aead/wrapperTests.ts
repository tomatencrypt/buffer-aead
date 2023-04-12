import AeadSpecifier from '../../../lib/types/AeadSpecifier';
import { assert } from 'assertthat';
import crypto from 'crypto';
import sinon from 'sinon';
import { tamperBuffer } from '../helpers';
import { aeads, defaultAead, wrapper } from '../../../lib/aead/wrapper';

const testVectors: Record<AeadSpecifier, Record<string, Buffer>> = {
  aesgcm: {
    // Official test vector from https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
    // Section B; Test Case 16
    key: Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex'),
    nonce: Buffer.from('cafebabefacedbaddecaf888', 'hex'),
    data: Buffer.from(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
      'hex'
    ),
    additionalData: Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'),
    ciphertext: Buffer.from(
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
      'hex'
    ),
    authTag: Buffer.from('76fc6ece0f4e1768cddf8853bb2d551b', 'hex')
  },

  aesctrhmac: {
    // Official test vector from https://datatracker.ietf.org/doc/html/rfc3686.html#page-9
    // Test Vector #7
    key: Buffer.from('776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104', 'hex'),
    nonce: Buffer.from('00000060DB5672C97AA8F0B200000001', 'hex'),
    data: Buffer.from('53696E676C6520626C6F636B206D7367', 'hex'),
    ciphertext: Buffer.from('145AD01DBF824EC7560863DC71E3E0C0', 'hex'),

    // Defined additionalData and tested authTag manually, before it was hard coded here
    additionalData: Buffer.from('010203', 'hex'),
    authTag: Buffer.from('5E788FDB1290D3E4872BAE4BE3921D77D4E1AD72AEF06525649E10D7A8C03F90', 'hex')
  },
  xchacha20poly1305: {}
};

const mockRandom = (testVector: Record<string, Buffer>): void => {
  sinon.restore();
  sinon.replace(crypto, 'randomBytes', (size: number): Buffer => size === testVector.nonce.length ? testVector.nonce : testVector.key);
};

const ensureRealRandom = (): void => {
  sinon.restore();
};

suite('AEADs', (): void => {
  for (const [ aeadName, aead ] of Object.entries(aeads)) {
    // TODO [2023-04-30]: remove this when all aeads implemented
    if (aeadName === 'xchacha20poly1305') {
      return;
    }

    suite(`AEAD: ${aeadName}`, (): void => {
      const testVector = testVectors[aeadName as AeadSpecifier];

      suite('wrapper', (): void => {
        if (aeadName === defaultAead) {
          test(`uses ${defaultAead} as default.`, async (): Promise<void> => {
            mockRandom(testVector);

            const key = wrapper.keyGen();
            const nonce = wrapper.nonceGen();
            const { ciphertext, authTag } = wrapper.encrypt({ data: testVector.data });
            const decrypted = wrapper.decrypt({ key, nonce, ciphertext, authTag });

            assert.that(key).is.equalTo(testVector.key);
            assert.that(nonce).is.equalTo(testVector.nonce);
            assert.that(ciphertext).is.equalTo(testVector.ciphertext);
            assert.that(decrypted).is.equalTo(testVector.data);
          });
        }

        test(`uses ${aeadName} if specified.`, async (): Promise<void> => {
          mockRandom(testVector);
          const specifiedAead = aeadName as AeadSpecifier;

          const key = wrapper.keyGen(specifiedAead);
          const nonce = wrapper.nonceGen(specifiedAead);
          const { ciphertext, authTag } = wrapper.encrypt({ data: testVector.data, aead: specifiedAead });
          const decrypted = wrapper.decrypt({ key, nonce, ciphertext, authTag, aead: specifiedAead });

          assert.that(key).is.equalTo(testVector.key);
          assert.that(nonce).is.equalTo(testVector.nonce);
          assert.that(ciphertext).is.equalTo(testVector.ciphertext);
          assert.that(decrypted).is.equalTo(testVector.data);
        });
      });

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
        const expectedErrorText = 'Unsupported state or unable to authenticate data';

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

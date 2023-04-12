import AeadSpecifier from '../../../lib/types/AeadSpecifier';
import { assert } from 'assertthat';
import crypto from 'crypto';
import sinon from 'sinon';
import { tamperBuffer } from '../helpers';
import { aeads, defaultAead, wrapper } from '../../../lib/aead/wrapper';

const testVectors: Record<AeadSpecifier, Record<string, Buffer>> = {
  aesgcm: {
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
  aesctrhmac: {},
  xchacha20poly1305: {}
};

suite('AEADs', (): void => {
  test(`uses ${defaultAead} as default.`, async (): Promise<void> => {
    const aead = defaultAead;
    const testVector = testVectors.aesgcm;

    const key = wrapper.keyGen(aead);
    const nonce = wrapper.nonceGen(aead);
    const { ciphertext, authTag } = wrapper.encrypt({ data: testVector.data, aead });
    const decrypted = wrapper.decrypt({ key, nonce, ciphertext, authTag, aead });

    assert.that(key).is.equalTo(testVector.key);
    assert.that(nonce).is.equalTo(testVector.nonce);
    assert.that(ciphertext).is.equalTo(testVector.ciphertext);
    assert.that(decrypted).is.equalTo(testVector.data);
  });

  for (const [ aeadName, aead ] of Object.entries(aeads)) {
    // TODO [2023-04-30]: remove this when all aeads implemented
    if (aeadName !== 'aesgcm') {
      return;
    }

    suite(`AEAD: ${aeadName}`, (): void => {
      const testVector = testVectors[aeadName as AeadSpecifier];

      sinon.restore();
      sinon.replace(crypto, 'randomBytes', (size: number): Buffer => size === testVector.nonce.length ? testVector.nonce : testVector.key);

      suite('generations', (): void => {
        test('returns correct key, using mocked random.', async (): Promise<void> => {
          const generatedKey = aead.keyGen();

          assert.that(generatedKey).is.equalTo(testVector.key);
        });

        test('returns correct nonce, using mocked random.', async (): Promise<void> => {
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
          const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

          const result = aead.encrypt({ data, nonce, additionalData });

          assert.that(result.ciphertext).is.equalTo(ciphertext);
          assert.that(result.authTag).is.equalTo(authTag);
          assert.that(result.key).is.equalTo(key);
        });

        test('encrypts correctly using official testvector, no nonce given.', async (): Promise<void> => {
          const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

          const result = aead.encrypt({ data, key, additionalData });

          assert.that(result.ciphertext).is.equalTo(ciphertext);
          assert.that(result.authTag).is.equalTo(authTag);
          assert.that(result.nonce).is.equalTo(nonce);
        });

        test('encrypts correctly using official testvector, no key and nonce given.', async (): Promise<void> => {
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
          const data = Buffer.alloc(32);
          // eslint-disable-next-line no-sync
          crypto.randomFillSync(data);

          const { key, nonce, ciphertext, authTag } = aead.encrypt({ data });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: data, key.', async (): Promise<void> => {
          const data = Buffer.alloc(32);
          // eslint-disable-next-line no-sync
          crypto.randomFillSync(data);

          const { key, nonce, ciphertext, authTag } = aead.encrypt({ data, key: data });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: data, nonce.', async (): Promise<void> => {
          const data = Buffer.alloc(32);
          // eslint-disable-next-line no-sync
          crypto.randomFillSync(data);

          const { key, nonce, ciphertext, authTag } = aead.encrypt({ data, nonce: data });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: data, key, nonce.', async (): Promise<void> => {
          const data = Buffer.alloc(32);
          // eslint-disable-next-line no-sync
          crypto.randomFillSync(data);

          const { key, nonce, ciphertext, authTag } = aead.encrypt({ data, key: data, nonce: data });
          const decrypted = aead.decrypt({ key, nonce, ciphertext, authTag });

          assert.that(decrypted).is.equalTo(data);
        });

        test('encrypts and decrypts back correctly, given: all.', async (): Promise<void> => {
          const data = Buffer.alloc(32);
          // eslint-disable-next-line no-sync
          crypto.randomFillSync(data);
          const additionalData = data;

          const { key, nonce, ciphertext, authTag } = aead.encrypt({ data, key: data, nonce: data, additionalData });
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

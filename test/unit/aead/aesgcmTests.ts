import aesgcm from '../../../lib/aead/aesgcm';
import { assert } from 'assertthat';
import crypto from 'crypto';
import sinon from 'sinon';
import { tamperBuffer } from '../helpers';

// Official test vector from https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
// Section B; Test Case 16
const testVector = {
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
};

sinon.replace(crypto, 'randomBytes', (size: number): Buffer => size === 12 ? testVector.nonce : testVector.key);

suite('AEAD aes-256-gcm', (): void => {
  suite('generations', (): void => {
    test('returns correct key, using mocked random.', async (): Promise<void> => {
      const generatedKey = aesgcm.keyGen();

      assert.that(generatedKey).is.equalTo(testVector.key);
    });

    test('returns correct nonce, using mocked random.', async (): Promise<void> => {
      const generatedNonce = aesgcm.nonceGen();

      assert.that(generatedNonce).is.equalTo(testVector.nonce);
    });
  });

  suite('encryption, using official test vector', (): void => {
    test('encrypts correctly using official testvector, all values given.', async (): Promise<void> => {
      const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

      const result = aesgcm.encrypt({ data, key, nonce, additionalData });

      assert.that(result.ciphertext).is.equalTo(ciphertext);
      assert.that(result.authTag).is.equalTo(authTag);
    });

    test('encrypts correctly using official testvector, no key given.', async (): Promise<void> => {
      const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

      const result = aesgcm.encrypt({ data, nonce, additionalData });

      assert.that(result.ciphertext).is.equalTo(ciphertext);
      assert.that(result.authTag).is.equalTo(authTag);
      assert.that(result.key).is.equalTo(key);
    });

    test('encrypts correctly using official testvector, no nonce given.', async (): Promise<void> => {
      const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

      const result = aesgcm.encrypt({ data, key, additionalData });

      assert.that(result.ciphertext).is.equalTo(ciphertext);
      assert.that(result.authTag).is.equalTo(authTag);
      assert.that(result.nonce).is.equalTo(nonce);
    });

    test('encrypts correctly using official testvector, no key and nonce given.', async (): Promise<void> => {
      const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

      const result = aesgcm.encrypt({ data, additionalData });

      assert.that(result.ciphertext).is.equalTo(ciphertext);
      assert.that(result.authTag).is.equalTo(authTag);
      assert.that(result.key).is.equalTo(key);
      assert.that(result.nonce).is.equalTo(nonce);
    });
  });

  suite('decryption, using official test vector', (): void => {
    test('decrypts correctly using official testvector.', async (): Promise<void> => {
      const { key, nonce, data, additionalData, ciphertext, authTag } = testVector;

      const decrypted = aesgcm.decrypt({ ciphertext, authTag, key, nonce, additionalData });

      assert.that(decrypted).is.equalTo(data);
    });
  });

  suite('encryption and decryption, using random values', (): void => {
    test('encrypts and decrypts back correctly, given: data.', async (): Promise<void> => {
      const data = Buffer.alloc(32);
      // eslint-disable-next-line no-sync
      crypto.randomFillSync(data);

      const { key, nonce, ciphertext, authTag } = aesgcm.encrypt({ data });
      const decrypted = aesgcm.decrypt({ key, nonce, ciphertext, authTag });

      assert.that(decrypted).is.equalTo(data);
    });

    test('encrypts and decrypts back correctly, given: data, key.', async (): Promise<void> => {
      const data = Buffer.alloc(32);
      // eslint-disable-next-line no-sync
      crypto.randomFillSync(data);

      const { key, nonce, ciphertext, authTag } = aesgcm.encrypt({ data, key: data });
      const decrypted = aesgcm.decrypt({ key, nonce, ciphertext, authTag });

      assert.that(decrypted).is.equalTo(data);
    });

    test('encrypts and decrypts back correctly, given: data, nonce.', async (): Promise<void> => {
      const data = Buffer.alloc(32);
      // eslint-disable-next-line no-sync
      crypto.randomFillSync(data);

      const { key, nonce, ciphertext, authTag } = aesgcm.encrypt({ data, nonce: data });
      const decrypted = aesgcm.decrypt({ key, nonce, ciphertext, authTag });

      assert.that(decrypted).is.equalTo(data);
    });

    test('encrypts and decrypts back correctly, given: data, key, nonce.', async (): Promise<void> => {
      const data = Buffer.alloc(32);
      // eslint-disable-next-line no-sync
      crypto.randomFillSync(data);

      const { key, nonce, ciphertext, authTag } = aesgcm.encrypt({ data, key: data, nonce: data });
      const decrypted = aesgcm.decrypt({ key, nonce, ciphertext, authTag });

      assert.that(decrypted).is.equalTo(data);
    });

    test('encrypts and decrypts back correctly, given: all.', async (): Promise<void> => {
      const data = Buffer.alloc(32);
      // eslint-disable-next-line no-sync
      crypto.randomFillSync(data);
      const additionalData = data;

      const { key, nonce, ciphertext, authTag } = aesgcm.encrypt({ data, key: data, nonce: data, additionalData });
      const decrypted = aesgcm.decrypt({ key, nonce, ciphertext, authTag, additionalData });

      assert.that(decrypted).is.equalTo(data);
    });
  });

  suite('authentication failueres', (): void => {
    const expectedErrorText = 'Unsupported state or unable to authenticate data';

    test('fails to decrypt due invalid ciphertext.', async (): Promise<void> => {
      const { key, nonce, additionalData, ciphertext, authTag } = testVector;
      const tampered = tamperBuffer(ciphertext);

      assert.that((): void => {
        aesgcm.decrypt({ ciphertext: tampered, authTag, key, nonce, additionalData });
      }).is.throwing(expectedErrorText);
    });

    test('fails to decrypt due invalid authTag.', async (): Promise<void> => {
      const { key, nonce, additionalData, ciphertext, authTag } = testVector;
      const tampered = tamperBuffer(authTag);

      assert.that((): void => {
        aesgcm.decrypt({ ciphertext, authTag: tampered, key, nonce, additionalData });
      }).is.throwing(expectedErrorText);
    });

    test('fails to decrypt due invalid additionalData.', async (): Promise<void> => {
      const { key, nonce, additionalData, ciphertext, authTag } = testVector;
      const tampered = tamperBuffer(additionalData);

      assert.that((): void => {
        aesgcm.decrypt({ ciphertext, authTag, key, nonce, additionalData: tampered });
      }).is.throwing(expectedErrorText);
    });

    test('fails to decrypt due invalid key.', async (): Promise<void> => {
      const { key, nonce, additionalData, ciphertext, authTag } = testVector;
      const tampered = tamperBuffer(key);

      assert.that((): void => {
        aesgcm.decrypt({ ciphertext, authTag, key: tampered, nonce, additionalData });
      }).is.throwing(expectedErrorText);
    });

    test('fails to decrypt due invalid nonce.', async (): Promise<void> => {
      const { key, nonce, additionalData, ciphertext, authTag } = testVector;
      const tampered = tamperBuffer(nonce);

      assert.that((): void => {
        aesgcm.decrypt({ ciphertext, authTag, key, nonce: tampered, additionalData });
      }).is.throwing(expectedErrorText);
    });
  });
});

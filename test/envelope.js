const assert = require('assert');
const envelopFuncs = require('../');
const crypto = require('crypto');

const tdkMock = {
  KeyId: 'arn:aws:kms:us-west-2:123456789:key/c7e52f9e-6e58-489d-bed7-363660bff277',
  CiphertextBlob: new Buffer('AQIDAHiKTWxtOUEeUjwjaNKh1r6z+E+MX1KoPAJuULn8uXauugErWloWc0AeQQd3E681O5bzAAAAfjB8Bgkqhki' +
    'G9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMZasGbqo1T6QVtMSjAgEQgDtDKOiUsYc31LvKYF0RfO7ba3m2qrB12Cf' +
    'SN5X6bH/P3Bb03JX3wtdMhTAAbtFrQEgYjjYNK3Y+2peqqg==', 'base64'),
  Plaintext: new Buffer('ZAsPrKgyKAyZ+9pKNqRsXlC0luk5uO9t5ekA8KFDwrg=', 'base64'),
};

const tmkMock = {
  KeyId: 'arn:aws:kms:us-west-2:123456789:key/c7e52f9e-6e58-489d-bed7-363660bff277',
  CiphertextBlob: new Buffer('AQIDAHiKTWxtOUEeUjwjaNKh1r6z+E+MX1KoPAJuULn8uXauugErWloWc0AeQQd3E681O5bzAAAAfjB8Bgkqhki' +
    'G9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMZasGbqo1T6QVtMSjAgEQgDtDKOiUsYc31LvKYF0RfO7ba3m2qrB12Cf' +
    'SN5X6bH/P3Bb03JX3wtdMhTAAbtFrQEgYjjYNK3Y+2peqqg==', 'base64'),
  Plaintext: new Buffer('ZAsPrKgyKAyZ+9pKNqRsXlC0luk5uO9t5ekA8KFDwrg=', 'base64'),
};

const kms = (mock) => ({
  generateDataKey: () => ({
    promise: () => Promise.resolve(mock),
  }),
  decrypt: () => ({
    promise: () => Promise.resolve({
      KeyId: mock.KeyId,
      Plaintext: mock.Plaintext,
    }),
  }),
  generateRandom: () => ({
    promise: () => Promise.resolve({
      Plaintext: crypto.randomBytes(32),
    }),
  }),
});

const { decrypt, encrypt } = envelopFuncs();

describe('test', () => {
  it('create tmk, create tdk, encrypt text, decrypt text', async () => {
    const dataPlainText = 'this is a secret';
    const { createTenantMasterKey, decryptTenantMasterKey } = envelopFuncs(kms(tmkMock));
    const tmk = (await createTenantMasterKey(tmkMock.KeyId));
    const { createDataKey } = envelopFuncs(kms(tdkMock));
    const tdk = (await createDataKey(tmk.plainText));
    const tmkDecrypted = await decryptTenantMasterKey(tmk.cipherText);
    assert(tmkDecrypted.plainText === tmk.plainText);
    const tdkDecryptedPlainText = decrypt(tmk.plainText)(tdk.cipherText);
    assert(tdkDecryptedPlainText === tdk.plainText);
    const dataCipherText = encrypt(tdk.plainText)(dataPlainText, 'utf8');
    const dataDecryptedPlainText = new Buffer(decrypt(tdkDecryptedPlainText)(dataCipherText), 'base64')
      .toString('utf8');
    assert(dataCipherText !== dataPlainText);
    assert(dataDecryptedPlainText === dataPlainText);
  });
  it('encryptedEnvelope, decryptedEnvelope', async () => {
    const { createTenantMasterKey } = envelopFuncs(kms(tmkMock));
    const tmk = await createTenantMasterKey(tmkMock.KeyId);
    const dataPlainText = 'this is a secret';
    const { encryptEnvelope, decryptEnvelope } = envelopFuncs(kms(tmkMock));
    const encryptedEnvelope = await encryptEnvelope(tmkMock.KeyId, tmk.cipherText)(dataPlainText);
    const decryptedEnvelope = await decryptEnvelope(encryptedEnvelope, 'utf8');
    assert(encryptedEnvelope.dataCipherText !== dataPlainText);
    assert(decryptedEnvelope.dataPlainText === dataPlainText);
  });
});

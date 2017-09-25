const crypto = require('crypto');
const { KMS } = require('aws-sdk');
const assert = require('assert');

assert(Boolean(process.env.CMKID));

const CMKID = process.env.CMKID;
const API_VERSION = '2014-11-01';
const REGION = 'us-west-2';
const ALGO = 'aes256';

const kms = new KMS({
  apiVersion: API_VERSION,
  region: REGION,
});

const encrypt = keyBase64 => (plainText, plainTextEnc = 'base64') => {
  const cipher = crypto.createCipher(ALGO, new Buffer(keyBase64, 'base64'));
  return (Buffer.concat([cipher.update(plainText, plainTextEnc), cipher.final()])).toString('base64');
};

const decrypt = keyBase64 => (cipherText, cipherTextEnc = 'base64') => {
  const decipher = crypto.createDecipher(ALGO, new Buffer(keyBase64, 'base64'));
  return (Buffer.concat([decipher.update(cipherText, cipherTextEnc), decipher.final()])).toString('base64');
};

const createTenantMasterKey = async (cmkId) => {
  const { KeyId, CiphertextBlob, Plaintext } = await kms.generateDataKey({
    KeyId: cmkId,
    KeySpec: 'AES_256',
  }).promise();
  return {
    plainText: Plaintext.toString('base64'),
    cipherText: CiphertextBlob.toString('base64'),
    cmkId: KeyId,
    createdAt: (new Date()).toISOString(),
  };
};

const decryptTenantMasterKey = async (cipherTextBase64) => {
  const result = await kms.decrypt({
    CiphertextBlob: new Buffer(cipherTextBase64, 'base64'),
  }).promise();
  return {
    cmkId: result.KeyId,
    plainText: result.Plaintext.toString('base64'),
  };
};

const createDataKey = async (tmkPlainText) => {
  const { Plaintext } = await kms.generateRandom({
    NumberOfBytes: 32,
  }).promise();
  const cipherText = encrypt(tmkPlainText)(Plaintext.toString('base64'));
  return {
    plainText: Plaintext.toString('base64'),
    cipherText,
    createdAt: (new Date()).toISOString(),
  };
};

const encryptEnvelope = (cmkid, tmkCipherText) => async (dataPlainText, inputEnc = 'utf8') => {
  const start = Date.now();
  const tmkPlainTextBase64 = await decryptTenantMasterKey(tmkCipherText);
  const tdk = await createDataKey(tmkPlainTextBase64.plainText);
  const dataCipherText = encrypt(tdk.plainText)(dataPlainText, inputEnc);
  return {
    cmkid,
    tmkCipherText,
    tdkCipherText: tdk.cipherText,
    dataCipherText,
    elapsed: (Math.round((Date.now() - start), 0)),
    createdAt: (new Date()).toISOString(),
  };
};

const decryptEnvelope = async (envelope, outputEnc = 'base64') => {
  const start = Date.now();
  const {
    tmkCipherText,
    tdkCipherText,
    dataCipherText,
  } = envelope;
  const { plainText: tmk, cmkId } = await decryptTenantMasterKey(tmkCipherText);
  const tdk = decrypt(tmk)(tdkCipherText);
  const dataPlainText = (new Buffer((decrypt(tdk)(dataCipherText)), 'base64')).toString(outputEnc);
  return {
    cmkId,
    dataPlainText,
    elapsed: (Math.round((Date.now() - start), 0)),
    decryptedAt: (new Date()).toISOString(),
  };
};

const stepByStep = async (cmkId, data) => {
  const { cipherText: tmkCipherText, plainText: tmkPlainText } = (await createTenantMasterKey(cmkId));
  const { cipherText: tdkCipherText, plainText: tdkPlainText } = (await createDataKey(tmkPlainText));
  const { plainText: tmkPlainTextDecrypted } = await decryptTenantMasterKey(tmkCipherText);
  assert(tmkPlainTextDecrypted === tmkPlainText);
  const tdkPlainTextDecrypted = decrypt(tmkPlainTextDecrypted)(tdkCipherText);
  assert(tdkPlainTextDecrypted === tdkPlainText);
  const dataCipherText = encrypt(tdkPlainText)(data, 'utf8');
  const dataPlainText = new Buffer(decrypt(tdkPlainText)(dataCipherText), 'base64').toString('utf8');
  assert(dataCipherText !== data);
  assert(dataPlainText === data);
  return tmkCipherText;
};

const helpers = async (cmkId, tmkCipherText, data) => {
  const encrypteEnvelope = await encryptEnvelope(cmkId, tmkCipherText)(data);
  const decrypteEnvelope = await decryptEnvelope(encrypteEnvelope, 'utf8');
  assert(encrypteEnvelope.dataCipherText !== data);
  assert(decrypteEnvelope.dataPlainText === data);
};

(async () => {
  const data = 'this is a secret';
  const tmkCipherText = await stepByStep(CMKID, data);
  await helpers(CMKID, tmkCipherText, data);
})().catch(console.log);

const crypto = require('crypto');
const ALGO = 'aes256';

module.exports = (kms) => {
  const encrypt = keyBase64 => (plainText, plainTextEnc = 'base64') => {
    const cipher = crypto.createCipher(ALGO, new Buffer(keyBase64, 'base64'));
    return (Buffer.concat([cipher.update(plainText, plainTextEnc), cipher.final()])).toString('base64');
  };

  const decrypt = keyBase64 => (cipherText, cipherTextEnc = 'base64') => {
    const decipher = crypto.createDecipher(ALGO, new Buffer(keyBase64, 'base64'));
    return (Buffer.concat([decipher.update(cipherText, cipherTextEnc), decipher.final()])).toString('base64');
  };

  const createTenantMasterKey = async (cmkId) => {
    const { KeyId, CiphertextBlob, Plaintext, abc } = await kms.generateDataKey({
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

  const encryptEnvelope = (cmkId, tmkCipherText) => async (dataPlainText, inputEnc = 'utf8') => {
    const tmkPlainTextBase64 = await decryptTenantMasterKey(tmkCipherText);
    const tdk = await createDataKey(tmkPlainTextBase64.plainText);
    const dataCipherText = encrypt(tdk.plainText)(dataPlainText, inputEnc);
    return {
      cmkId,
      tmkCipherText,
      tdkCipherText: tdk.cipherText,
      dataCipherText,
      createdAt: (new Date()).toISOString(),
    };
  };

  const decryptEnvelope = async (envelope, outputEnc = 'base64') => {
    const {
      tmkCipherText,
      tdkCipherText,
      dataCipherText,
    } = envelope;
    const tmk = await decryptTenantMasterKey(tmkCipherText);
    const tdk = decrypt(tmk.plainText)(tdkCipherText);
    const dataPlainText = (new Buffer((decrypt(tdk)(dataCipherText)), 'base64')).toString(outputEnc);
    return {
      cmkId: tmk.cmkId,
      dataPlainText,
      decryptedAt: (new Date()).toISOString(),
    };
  };

  return {
    encrypt,
    decrypt,
    createTenantMasterKey,
    decryptTenantMasterKey,
    createDataKey,
    encryptEnvelope,
    decryptEnvelope,
  };
};

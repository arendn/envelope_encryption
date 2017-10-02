/* const assert = require('assert');
const {
  encrypt,
  decrypt,
  createTenantMasterKey,
  createDataKey,
  decryptTenantMasterKey
} = require('../index.js');

describe('', () => {
  it('', async () => {
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
  });
});*/

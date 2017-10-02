#!/usr/bin/env node
const assert = require('assert');
const prettyjson = require('prettyjson');
const { KMS } = require('aws-sdk');
const kms = new KMS({ apiVersion: '2014-11-01', region: 'us-west-2' });

const {
  createTenantMasterKey,
  encryptEnvelope,
  decryptEnvelope,
} = require('.')(kms);

if (!process.env.CMKID) {
  console.log('Please set the the AWS KMS key you\'d like to use on the $CMKID environment variable');
  process.exit();
}

const cmkId = process.env.CMKID;

(async () => {
  const data = 'this is a secret';
  const tmk = await createTenantMasterKey(cmkId);
  const encryptedEnvelope = await encryptEnvelope(cmkId, tmk.cipherText)(data);
  console.log('\nEncrypted Envelope:');
  console.log(prettyjson.render(encryptedEnvelope));
  const decryptedEnvelope = await decryptEnvelope(encryptedEnvelope, 'utf8');
  console.log('\nDecrypted Envelope:');
  console.log(prettyjson.render(encryptedEnvelope));
  assert(encryptedEnvelope.dataCipherText !== data);
  assert(decryptedEnvelope.dataPlainText === data);
})().catch(console.log);

#envelop_encryption demo

# Concepts
* CMK: Customer Master Key - (AWS Concept): represented by a ARN value
* TMK: Tenant Master Key - (implementation concept): represents the per customer key
* TDK: Tenant Data Key - (implementation concept):  represents the per customer data item


# Demo
**NB: Requires KMS ARN to be the specified  environment var CMKID**

```bash
export CMKID=arn:aws:kms:{yourregion}:{youraccount}:key/{yourkeyId}
npm run demo
``` 
# Tests
```bash
npm test
``` 
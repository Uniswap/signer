# Signer

This package contains classes to sign and broadcast cryptographic messages.

## Testing
Here are the following commands to test the code in this package. Whenever making changes to this package we should run the manual integration tests to ensure that the changes are not breaking. 

### Unit tests
```
yarn test:unit
```
### Integration tests
In order to run manual integration tests we need to deploy a Key to our local AWS Key Managment Service (KMS). This is the CDK code to create a local key.
```
import * as cdk from 'aws-cdk-lib'
import { CfnOutput, RemovalPolicy } from 'aws-cdk-lib'
import { KeySpec, KeyUsage } from 'aws-cdk-lib/aws-kms'
import { Construct } from 'constructs'

export class KmsStack extends cdk.NestedStack {
  public readonly key: cdk.aws_kms.Key

  constructor(parent: Construct, name: string) {
    super(parent, name)

    /**
     * Unless absolutely necessary, DO NOT change this construct.
     * This uses the 'Retain' DeletionPolicy, which will cause the resource to be retained
     * in the account, but orphaned from the stack if the Key construct is ever changed.
     */
    this.key = new cdk.aws_kms.Key(this, name, {
      removalPolicy: RemovalPolicy.RETAIN,
      keySpec: KeySpec.ECC_SECG_P256K1,
      keyUsage: KeyUsage.SIGN_VERIFY,
      alias: name,
    })

    new CfnOutput(this, `${name}KeyId`, {
      value: this.key.keyId,
    })
  }
}
```
We then need to add the following variables to our `.env` file.
```
KMS_KEY_ID=<key_id>
REGION=<region>
// We can get this from running integration tests on MAIN and checking the output of signer.getAddress().
ETHEREUM_ADDRESS_OF_KMS_KEY=<address>
```
Then run this test command.
```
yarn test:manual_integ
```
### All tests
```
yarn test:all
```
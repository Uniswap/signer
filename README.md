# Signer

This package contains an abstract class `AwsSigner`, and its implementation `KmsSigner` that,
given a [KmsClient](https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-kms) and a `keyId`,
it provides methods for signing Ethereum transactions.

## Testing
The integration & unit tests run as part of the same suite. 

### Running tests
In order to run the tests we need to run a local-kms service on port 8080.
We can use [nsmithuk/local-kms](https://github.com/nsmithuk/local-kms) with docker.

Simply run, and make sure the container is running before executing the tests.
```shell
docker run -p 8080:8080 nsmithuk/local-kms
yarn test
```

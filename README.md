# Signer

This package contains an abstract class `AwsSigner`, and its implementation `KmsSigner` that,
given a [KmsClient](https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-kms) and a `keyId`,
it provides methods for signing Ethereum transactions.

## Testing
Here are the following commands to test the code in this package. Whenever making changes to this package we should run the manual integration tests to ensure that the changes are not breaking. 

### Unit tests
```shell
yarn test:unit
```
### Integration tests
In order to run integration tests we need to run a local-kms service on port 8080.
We can use [nsmithuk/local-kms](https://github.com/nsmithuk/local-kms) with docker.

Simply run, and make sure the container is running before executing the integration tests.
```shell
docker run -p 8080:8080 nsmithuk/local-kms
yarn test:integ
```
### All tests
```shell
yarn test:all
```

import {checkDefined} from '@uniswap/utils';
import * as dotenv from 'dotenv';
import {KmsSigner} from 'src/signer/aws-signer/KmsSigner';
import {describe, expect, it} from 'vitest';

/**
 * TODO(mikeki): This integration test can only be run manually right now
 * because it requires a local KMS stack deploy. We have a yarn test:manual_integ command
 * in the meantime. We should look into using a localstack or local KMS emulator and change
 * this test to run during the CI. For more info on how to run this test see the REAME.md.
 */
dotenv.config();
describe('KmsSigner', () => {
  const keyId = checkDefined(
    process.env['KMS_KEY_ID'],
    'KMS_KEY_ID needs to be defined'
  );
  const region = checkDefined(
    process.env['REGION'],
    'REGION needs to be defined'
  );
  const ethereumAddressOfKmsKey = checkDefined(
    process.env['ETHEREUM_ADDRESS_OF_KMS_KEY'],
    'ETHEREUM_ADDRESS_OF_KMS_KEY needs to be defined'
  );

  const signer = new KmsSigner(keyId, region);

  it('getAddress', async () => {
    const address = await signer.getAddress();
    expect(address).toBe(ethereumAddressOfKmsKey);
  });
  it('signMessage', async () => {
    const msg = 'Hello World';
    const signature = await signer.signMessage(msg);
    expect(signature.startsWith('0x')).toBeTruthy();
  });
  it('recoverAddressFromSig', async () => {
    const msg = 'Hello World';
    const signature = await signer.signMessage(msg);

    const address = await signer.getAddress();
    const recovered = signer.recoverAddressFromSig(msg, signature);
    expect(address).toBe(recovered);
  });
  it('signTransaction', async () => {
    const address = await signer.getAddress();
    const transaction: any = {
      to: address,
      data: '0x12345678',
      value: '0x',
      chainId: 1,
    };

    const txSignature = await signer.signTransaction(transaction);
    expect(txSignature.startsWith('0x')).toBeTruthy();

    const recovered = await signer.recoverAddressFromTxSig(
      transaction,
      txSignature
    );
    expect(address).toBe(recovered);
  });
});

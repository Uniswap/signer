import {
  CreateKeyCommand,
  KeySpec,
  KeyUsageType,
  KMSClient,
} from '@aws-sdk/client-kms';
import {KmsSigner} from 'src/signer/aws-signer/KmsSigner';
import {beforeAll, describe, expect, it} from 'vitest';

describe('KmsSigner', () => {
  let signer: KmsSigner;

  beforeAll(async () => {
    const client = new KMSClient({
      endpoint: 'http://localhost:8080',
    });
    const createKeyCommand = new CreateKeyCommand({
      KeySpec: KeySpec.ECC_SECG_P256K1,
      KeyUsage: KeyUsageType.SIGN_VERIFY,
    });
    const createKeyResponse = await client.send(createKeyCommand);
    const keyId = createKeyResponse.KeyMetadata?.KeyId;
    signer = new KmsSigner(client, keyId!);
  });

  it('getAddress', async () => {
    const address = await signer.getAddress();
    expect(address).toBeDefined();
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
      value: '0x0',
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

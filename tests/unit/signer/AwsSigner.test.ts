import {AwsSigner} from 'src/signer/aws-signer/AwsSigner';
import {describe, expect, it} from 'vitest';

const ADDRESS = '0x61Fb9b83Ece274BdE3d1640dA6A394552a2eCC63';

export class AwsSignerTestInstance extends AwsSigner {
  async getAddress(): Promise<string> {
    return ADDRESS;
  }

  async signMessage(): Promise<string> {
    throw new Error('Method not implemented.');
  }

  async signTransaction(): Promise<string> {
    throw new Error('Method not implemented.');
  }

  signTypedData(): Promise<string> {
    throw new Error('Method not implemented.');
  }

  signDigest(digest: Buffer | string): Promise<string> {
    throw new Error('Method not implemented.');
  }
}

describe('AwsSigner', () => {
  const signer = new AwsSignerTestInstance();

  describe('recoverAddressFromSig', () => {
    const validSignature =
      '0x9cce16c639046f30677cdc6dd2a146e15a70f3ed7b7d11fb133cfebeb5cf2e2d1a10fb12e2519f0a8cef65349261d68336e2a44f0e31989032c0dd0181d6cd3b1b';

    it('properly recovers address from valid signature', async () => {
      const msg = 'Hello World';
      const recovered = signer.recoverAddressFromSig(msg, validSignature);
      expect(recovered).toBe(ADDRESS);
    });

    it('recovers different address from modified but still valid signature', async () => {
      const msg = 'Hello World';
      const modifiedSignature =
        '0x9ccc16c639046f30677cdc6dd2a146e15a70f3ed7b7d11fb133cfebeb5cf2e2d1a10fb12e2519f0a8cef65349261d68336e2a44f0e31989032c0dd0181d6cd3b1b';

      expect(modifiedSignature).not.toBe(validSignature);
      const recovered = signer.recoverAddressFromSig(msg, modifiedSignature);
      expect(recovered).not.toBe(ADDRESS);
    });

    it('throws error on invalid signature recover', async () => {
      const msg = 'Hello World';
      const invalidSignature =
        '0x9cce16c639046f30677cdc6dd2a146e15a70f3ed7b7d11fb133cfebeb5cf2e2d1a10fb12e2519f0a8cef65349261d68336e2a44f0e31989032c0dd0181d6cd3b1r';

      expect(invalidSignature).not.toBe(validSignature);
      expect(() => {
        signer.recoverAddressFromSig(msg, invalidSignature);
      }).toThrowError('INVALID_ARGUMENT');
    });
  });

  describe('recoverAddressFromTxSig', () => {
    const validSignature =
      '0x02f86401808080809461fb9b83ece274bde3d1640da6a394552a2ecc63808412345678c080a0b118e3a53cf9eaa665b2385307d2d2a2acec8aa0dbfcf71e8e9f7ac728332d74a0594eb3aa671a7b6d25dfdfb29addbb79f59b31a4b1cf002c91e835d6b20e1934';
    const tx = {
      to: '0x61Fb9b83Ece274BdE3d1640dA6A394552a2eCC63',
      data: '0x12345678',
      value: '0x0',
      chainId: 1,
    };

    it('properly recovers address from tx and signature', async () => {
      const recovered = await signer.recoverAddressFromTxSig(
        tx,
        validSignature
      );
      expect(recovered).toBe(ADDRESS);
    });

    it('recovers different address from modified but still valid signature', async () => {
      const modifiedSignature =
        '0xf8618080809461fb9b83ece274bde3d1640da6a394552a2ecc6380841234567825a0c917c5ffb7d7ef95897bcbe090b4b388278e69b8205746f5d8ce136b0aa50efea00864f1eaa9ef8aa69acc221be4fc0b0e576c40310d26dffe574edb9798db61a5';

      expect(modifiedSignature).not.toBe(validSignature);
      const recovered = await signer.recoverAddressFromTxSig(
        tx,
        modifiedSignature
      );
      expect(recovered).not.toBe(ADDRESS);
    });

    it('throws error on invalid signature recover', async () => {
      const invalidSignature =
        '0x02f86401808080809461fb9b83ece274bde3d1640da6a394552a2ecc63808412345678c080a0b118e3a53cf9eaa665b2385307d2d2a2acec8aa0dbfcf71e8e9f7ac728332d74a0594eb3aa671a7b6d25dfdfb29addbb79f59b31a4b1cf002c91e835d6b';
      expect(invalidSignature).not.toBe(validSignature);
      expect(async () => {
        await signer.recoverAddressFromTxSig(tx, invalidSignature);
      }).rejects.toThrowError('invalid BytesLike value');
    });
  });

  describe('getEthereumAddress', () => {
    const validPublicKeyBuffer = Buffer.from([
      48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 10,
      3, 66, 0, 4, 87, 202, 103, 165, 19, 10, 177, 50, 158, 213, 207, 93, 82,
      189, 40, 128, 20, 224, 243, 125, 34, 179, 119, 116, 73, 48, 94, 225, 217,
      83, 234, 72, 38, 68, 50, 93, 170, 57, 79, 192, 55, 79, 130, 216, 172, 233,
      180, 14, 145, 34, 3, 252, 191, 22, 17, 131, 18, 190, 144, 163, 211, 100,
      42, 138,
    ]);

    it('get ethereum address from valid KMS public key buffer', async () => {
      const address = signer.getEthereumAddress(validPublicKeyBuffer);
      expect(address).toBe(ADDRESS);
    });

    it('get ethereum address from modified KMS public key buffer recovers different address', async () => {
      const modifiedPublicKeyBuffer = Buffer.from([
        48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0,
        10, 3, 66, 0, 4, 87, 202, 103, 165, 19, 10, 177, 50, 158, 213, 207, 93,
        82, 189, 40, 128, 20, 224, 243, 125, 34, 179, 119, 116, 73, 48, 94, 225,
        217, 83, 234, 72, 38, 68, 50, 93, 171, 57, 79, 192, 55, 79, 130, 216,
        172, 233, 180, 14, 145, 34, 3, 252, 191, 22, 17, 131, 18, 190, 144, 163,
        211, 100, 42, 138,
      ]);

      expect(validPublicKeyBuffer.equals(modifiedPublicKeyBuffer)).toBe(false);
      const address = signer.getEthereumAddress(modifiedPublicKeyBuffer);
      expect(address).not.toBe(ADDRESS);
    });

    it('throws error recovering invalid public key buffer', async () => {
      const invalidPublicKeyBuffer = Buffer.from([
        48, 86, 45, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0,
        10, 3, 66, 0, 4, 87, 202, 103, 165, 19, 10, 177, 50, 158, 213, 207, 93,
        82, 189, 40, 128, 20, 224, 243, 125, 34, 179, 119, 116, 73, 48, 94, 225,
        217, 83, 234, 72, 38, 68, 50, 93, 171, 57, 79, 192, 55, 79, 130, 216,
        172, 233, 180, 14, 145, 34, 3, 252, 191, 22, 17, 131, 18, 190, 144, 163,
        211, 100, 42, 138,
      ]);

      expect(validPublicKeyBuffer.equals(invalidPublicKeyBuffer)).toBe(false);
      expect(() => {
        signer.getEthereumAddress(invalidPublicKeyBuffer);
      }).toThrowError();
    });
  });

  describe('getJoinedSignature', () => {
    it('get signature from msg and signature buffer', async () => {
      const msgBuffer = Buffer.from([
        141, 198, 21, 192, 49, 254, 212, 125, 116, 129, 210, 80, 248, 201, 27,
        79, 94, 254, 91, 87, 204, 75, 43, 178, 232, 14, 29, 210, 128, 211, 119,
        88,
      ]);
      const signatureBuffer = Buffer.from([
        48, 68, 2, 32, 100, 11, 152, 149, 198, 140, 255, 76, 28, 197, 217, 187,
        19, 51, 120, 29, 109, 228, 78, 209, 225, 134, 198, 146, 36, 70, 149,
        247, 201, 174, 208, 106, 2, 32, 0, 235, 166, 138, 103, 165, 42, 183,
        191, 186, 136, 211, 55, 153, 83, 255, 78, 89, 199, 26, 191, 145, 57,
        102, 67, 190, 246, 32, 217, 41, 16, 211,
      ]);
      const expectedJoinedSignature =
        '0x640b9895c68cff4c1cc5d9bb1333781d6de44ed1e186c692244695f7c9aed06a00eba68a67a52ab7bfba88d3379953ff4e59c71abf91396643bef620d92910d31c';

      const joinedSignature = await signer.getJoinedSignature(
        msgBuffer,
        signatureBuffer
      );
      expect(joinedSignature).toBe(expectedJoinedSignature);
    });

    it('throws error for invalid signature with mismatched address', async () => {
      const msgBuffer = Buffer.from([
        141, 198, 21, 192, 49, 254, 212, 125, 116, 129, 210, 80, 248, 201, 27,
        79, 94, 254, 90, 87, 204, 75, 43, 178, 232, 14, 29, 210, 128, 211, 119,
        88,
      ]);
      const signatureBuffer = Buffer.from([
        48, 68, 2, 32, 100, 11, 152, 149, 198, 140, 255, 76, 28, 197, 217, 187,
        19, 51, 120, 29, 109, 228, 78, 209, 225, 134, 198, 146, 36, 70, 149,
        247, 201, 174, 208, 106, 2, 32, 0, 235, 166, 138, 103, 165, 42, 183,
        191, 186, 136, 211, 55, 153, 83, 255, 78, 89, 199, 26, 191, 145, 57,
        102, 67, 190, 246, 32, 217, 41, 16, 211,
      ]);

      expect(async () => {
        await signer.getJoinedSignature(msgBuffer, signatureBuffer);
      }).rejects.toThrowError(
        'signature is invalid. recovered address does not match'
      );
    });
  });
});

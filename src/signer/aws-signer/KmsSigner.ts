import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
  SignCommandInput,
} from '@aws-sdk/client-kms';
import {providers} from 'ethers';
import {
  arrayify,
  hashMessage,
  keccak256,
  resolveProperties,
  serializeTransaction,
  UnsignedTransaction,
} from 'ethers/lib/utils';

import {AwsSigner} from './AwsSigner';

export type KmsClientSignResponse = {
  Signature: Uint8Array;
};
export type KmsClientPublicKeyResponse = {
  PublicKey: Uint8Array;
};

/**
 * KmsSigner extends the AwsSigner class and fetches key data from AWS KMS for Ethereum
 * transaction and message signing. It implements methods to extract Ethereum addresses
 * from KMS public keys, sign messages, and generate EVM-compatible signatures. This class
 * also inherits functions from the ethers.js Signer class.
 *
 * NOTE: If making changes to this class test your changes by running the integration test
 * suit with yarn test:integ. In order to run these tests you will need to deploy a key
 * construct to your local KMS and add the KMS_KEY_ID, REGION, and address to your
 * environment variables.
 */
export class KmsSigner extends AwsSigner {
  private address: string;
  client: KMSClient;

  constructor(
    protected readonly keyId: string,
    public readonly region: string
  ) {
    super(keyId);
    this.client = new KMSClient({region});
  }

  connect(): KmsSigner {
    return this;
  }

  async getAddress(): Promise<string> {
    if (this.address) {
      return this.address;
    }
    const publicKey = await this.getPublicKey();
    const address = this.getEthereumAddress(publicKey);
    this.address = address;
    return address;
  }

  async signMessage(msg: Buffer | string): Promise<string> {
    const hash = hashMessage(msg);
    return this.signDigest(hash);
  }

  async signTransaction(
    transaction: providers.TransactionRequest
  ): Promise<string> {
    const normalizedTransaction = this.normalizeTransaction(transaction);
    const unsignedTx = (await resolveProperties(
      normalizedTransaction
    )) as UnsignedTransaction;
    const serializedTx = serializeTransaction(unsignedTx);
    const hash = keccak256(serializedTx);
    const txSig: string = await this.signDigest(hash);
    return serializeTransaction(unsignedTx, txSig);
  }

  private async signDigest(digest: Buffer | string): Promise<string> {
    const msg = Buffer.from(arrayify(digest));
    const signature: Buffer = await this.getSig(msg);
    return this.getJoinedSignature(msg, signature);
  }

  protected async getPublicKey(): Promise<Buffer> {
    const command = new GetPublicKeyCommand({
      KeyId: this.keyId,
    });
    const res = (await this.client.send(command)) as KmsClientPublicKeyResponse;
    return Buffer.from(res.PublicKey);
  }

  private async getSig(msg: Buffer): Promise<Buffer> {
    const params: SignCommandInput = {
      KeyId: this.keyId,
      Message: msg,
      SigningAlgorithm: 'ECDSA_SHA_256',
      MessageType: 'DIGEST',
    };
    const command = new SignCommand(params);
    const res = (await this.client.send(command)) as KmsClientSignResponse;
    return Buffer.from(res.Signature);
  }
}

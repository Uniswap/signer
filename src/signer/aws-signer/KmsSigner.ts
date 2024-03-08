import {
  GetPublicKeyCommand,
  KMSClient,
  MessageType,
  SignCommand,
  SignCommandInput,
  SigningAlgorithmSpec,
} from '@aws-sdk/client-kms';
import {
  getBytes,
  hashMessage,
  keccak256,
  resolveProperties,
  Transaction,
  TransactionRequest,
  TypedDataDomain,
  TypedDataEncoder,
  TypedDataField,
} from 'ethers';
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
 * NOTE: If making changes to this class test your changes by running the test suit
 * with `yarn test`. Make sure you have the local KMS container running.
 * See README.md for instructions
 */
export class KmsSigner extends AwsSigner {
  private address?: string;

  constructor(
    protected readonly client: KMSClient,
    protected readonly keyId: string
  ) {
    super();
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
    const signed = await this.signDigest(hash);
    return signed;
  }

  async signTransaction(transaction: TransactionRequest): Promise<string> {
    const normalizedTransaction = this.normalizeTransaction(transaction);
    const unsignedTx = (await resolveProperties(
      normalizedTransaction
    )) as Transaction;
    const serializedTx = Transaction.from(unsignedTx).unsignedSerialized;
    const hash = keccak256(serializedTx);
    const txSig: string = await this.signDigest(hash);
    unsignedTx.signature = txSig;
    return Transaction.from(unsignedTx).serialized;
  }

  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    value: Record<string, any>
  ): Promise<string> {
    const hash = TypedDataEncoder.hash(domain, types, value);
    return this.signDigest(hash);
  }

  async signDigest(digest: Buffer | string): Promise<string> {
    const msg = Buffer.from(getBytes(digest));
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
      SigningAlgorithm: SigningAlgorithmSpec.ECDSA_SHA_256,
      MessageType: MessageType.DIGEST,
    };
    const command = new SignCommand(params);
    const res = (await this.client.send(command)) as KmsClientSignResponse;
    return Buffer.from(res.Signature);
  }
}

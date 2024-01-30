// @ts-ignore
import * as asn1 from 'asn1.js';
import {BigNumber, providers, Signer} from 'ethers';
import {
  getAddress as checksumAddress,
  joinSignature,
  keccak256,
  parseTransaction,
  recoverAddress,
  resolveProperties,
  serializeTransaction,
  UnsignedTransaction,
  verifyMessage,
} from 'ethers/lib/utils';

import {addressEquals} from '../../util/address';

const EcdsaPubKey = asn1.define(
  'EcdsaPubKey',
  function (this: {seq: Function; key: Function}) {
    this.seq().obj(
      this.key('algo').seq().obj(this.key('a').objid(), this.key('b').objid()),
      this.key('pubKey').bitstr()
    );
  }
);

const EcdsaSigAsnParse = asn1.define(
  'EcdsaSig',
  function (this: {seq: Function; key: Function}) {
    this.seq().obj(this.key('r').int(), this.key('s').int());
  }
);

/**
 * Represents an AWS signer extending the Ethers.js Signer class.
 * This class is responsible for signing Ethereum transactions and messages using AWS.
 *
 * This class was heavily based off existing open source work. For more details see the below links.
 * @see {@link https://docs.aws.amazon.com/kms/latest/developerguide/programming-keys.html AWS KMS Programming Keys}
 * @see {@link https://github.com/hop-protocol/hop/blob/v0.0.169/packages/hop-node/src/aws/AwsSigner.ts Hop Protocol Implementation}
 * @see {@link https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81 Step by step guide of AWS signing}
 * @see {@link https://github.com/lucashenning/aws-kms-ethereum-signing/blob/master/aws-kms-sign.ts More details}
 */
export abstract class AwsSigner extends Signer {
  abstract getAddress(): Promise<string>;
  abstract signMessage(msg: Buffer | string): Promise<string>;
  abstract signTransaction(
    transaction: providers.TransactionRequest
  ): Promise<string>;

  constructor(protected readonly keyId: string) {
    super();
  }

  recoverAddressFromSig(msg: Buffer | string, signature: string): string {
    return verifyMessage(msg, signature);
  }

  async recoverAddressFromTxSig(
    transaction: providers.TransactionRequest,
    signature: string
  ): Promise<string> {
    const normalizedTransaction = this.normalizeTransaction(transaction);
    const unsignedTx = (await resolveProperties(
      normalizedTransaction
    )) as UnsignedTransaction;
    const serializedTx = serializeTransaction(unsignedTx);
    const hash = keccak256(serializedTx);

    const parsedTransaction = parseTransaction(signature);
    const {r, s, v} = parsedTransaction;
    if (!r || !s || !v) {
      throw new Error('signature is invalid. r, s, and v are required');
    }

    return recoverAddress(hash, {r, s, v});
  }

  getEthereumAddress(publicKey: Buffer): string {
    // Parses an ASN1 encoded public key according to the RFC 5480 standard (see: https://tools.ietf.org/html/rfc5480#section-2).
    const res = EcdsaPubKey.decode(publicKey, 'der');

    // The public key starts with a 0x04 prefix that needs to be removed.
    const pubKeyBuffer = res.pubKey.data.slice(1);

    const pubKeyHash = keccak256(pubKeyBuffer);
    const address = `0x${pubKeyHash.slice(-40)}`;
    return checksumAddress(address);
  }

  normalizeTransaction(
    transaction: providers.TransactionRequest
  ): providers.TransactionRequest {
    // Ethers will not serialize a transaction with a from address
    const normalizedTransaction = {...transaction};
    if (normalizedTransaction?.from) {
      delete normalizedTransaction.from;
    }
    return normalizedTransaction;
  }

  async getJoinedSignature(msg: Buffer, signature: Buffer): Promise<string> {
    const {r, s} = this.getSigRs(signature);
    const v = await this.getSigV(msg, {r, s});
    const joinedSignature = joinSignature({r, s, v});
    return joinedSignature;
  }

  async getSigV(
    msgHash: Buffer,
    {r, s}: {r: string; s: string}
  ): Promise<number> {
    const address = await this.getAddress();
    let v = 27;
    let recovered = recoverAddress(msgHash, {r, s, v});
    if (!addressEquals(recovered, address)) {
      v = 28;
      recovered = recoverAddress(msgHash, {r, s, v});
    }
    if (!addressEquals(recovered, address)) {
      throw new Error('signature is invalid. recovered address does not match');
    }

    return v;
  }

  getSigRs(signature: Buffer): {r: string; s: string} {
    const decoded = EcdsaSigAsnParse.decode(signature, 'der');
    const rBn = BigNumber.from(`0x${decoded.r.toString(16)}`);
    let sBn = BigNumber.from(`0x${decoded.s.toString(16)}`);
    // max value on the curve - https://www.secg.org/sec2-v2.pdf
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.8.3/contracts/utils/cryptography/ECDSA.sol#L138-L149
    const secp256k1N = BigNumber.from(
      '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
    );
    const secp256k1halfN = secp256k1N.div(BigNumber.from(2));

    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    if (sBn.gt(secp256k1halfN)) {
      sBn = secp256k1N.sub(sBn);
    }
    const r = rBn.toHexString();
    const s = sBn.toHexString();
    return {r, s};
  }
}

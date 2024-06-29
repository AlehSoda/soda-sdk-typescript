/// <reference types="node" resolution-mode="require"/>
/// <reference types="node" resolution-mode="require"/>
import crypto from "crypto";
import { ethers } from "ethers";
export declare function encryptAES(plaintext: Buffer, key: Buffer): {
    ciphertext: Buffer;
    r: Buffer;
};
export declare function decryptAES(ciphertext: Buffer, key: Buffer, r: Buffer): Buffer;
export declare function generateRSAKeyPair(): crypto.KeyPairSyncResult<Buffer, Buffer>;
export declare function decryptRSA(privateKey: Buffer, ciphertext: Buffer): Buffer;
export declare function decryptValue(ctAmount: bigint, userKey: string): number;
export declare function signRawMessage(message: string | Buffer, walletSigningKey: string): Buffer;
export declare function prepareMessage(plaintext: bigint, wallet: ethers.BaseWallet, aesKey: string, contractAddress: string, functionSelector: string): {
    ctInt: bigint;
    messageHash: string;
};
//# sourceMappingURL=crypto.d.ts.map
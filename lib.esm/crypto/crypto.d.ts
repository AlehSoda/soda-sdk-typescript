/// <reference types="node" resolution-mode="require"/>
/// <reference types="node" resolution-mode="require"/>
import crypto from "crypto";
import { BaseWallet } from "ethers";
export declare function generateRSAKeyPair(): crypto.KeyPairSyncResult<Buffer, Buffer>;
export declare function decryptRSA(privateKey: Buffer, ciphertext: Buffer): Buffer;
export declare function decryptValue(ctAmount: bigint, userKey: string): number;
export declare function sign(message: string, privateKey: string): Buffer;
export declare function prepareIT(plaintext: bigint, wallet: BaseWallet, userKey: string, contractAddress: string, functionSelector: string): Promise<{
    encryptedSecret: bigint;
    signature: Buffer;
}>;
export declare function createRandomUserKey(): string;
//# sourceMappingURL=crypto.d.ts.map
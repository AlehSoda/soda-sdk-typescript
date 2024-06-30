/// <reference types="node" />
/// <reference types="node" />
import crypto from "crypto";
export declare function encryptAES(plaintext: string, key: string): {
    ciphertext: Buffer;
    r: Buffer;
};
export declare function decryptAES(ciphertext: Buffer, key: Buffer, r: Buffer): Buffer;
export declare function generateRSAKeyPair(): Promise<crypto.KeyPairSyncResult<Buffer, Buffer>>;
export declare function decryptRSA(ciphertext: Buffer, privateKey: Buffer): Buffer;
export declare function decryptValue(ctAmount: bigint, aesKey: string): number;
export declare function signRawMessage(message: string | Buffer, walletSigningKey: string): Buffer;
export declare function prepareMessage(plaintext: bigint, signerAddress: string, aesKey: string, contractAddress: string, functionSelector: string): {
    encryptedInt: bigint;
    messageHash: string;
};
//# sourceMappingURL=crypto.d.ts.map
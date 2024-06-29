/// <reference types="node" resolution-mode="require"/>
import { ethers } from "ethers";
declare global {
    interface Window {
    }
    const window: Window;
    const self: Window;
}
export declare function generateRSAKeyPair(): Promise<{
    publicKey: any;
    privateKey: any;
}>;
export declare function decryptAES(key: string, r: string, ciphertext: string): string;
export declare function decryptValue(ctAmount: bigint, userKey: string): number;
export declare function prepareMessage(plaintext: bigint, wallet: ethers.BaseWallet, aesKey: string, contractAddress: string, functionSelector: string): {
    ctInt: bigint;
    messageHash: string;
};
export declare function encryptAES(key: string, plaintext: string): {
    ciphertext: string;
    r: string;
};
export declare function signRawMessage(message: string | Buffer, walletSigningKey: string): Buffer;
export declare function decryptRSA(privateKey: any, encryptedData: ArrayBuffer): Promise<ArrayBuffer>;
//# sourceMappingURL=crypto-browser.d.ts.map
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
export declare function encryptAES(plaintext: Uint8Array, key: Uint8Array): {
    ciphertext: string;
    r: string;
};
export declare function decryptAES(ciphertext: Uint8Array, key: Uint8Array, r: Uint8Array): Uint8Array;
export declare function decryptValue(ctAmount: bigint, userKey: string): void;
export declare function prepareMessage(plaintext: bigint, wallet: ethers.BaseWallet, aesKey: string, contractAddress: string, functionSelector: string): void;
export declare function signRawMessage(message: string | Buffer, walletSigningKey: string): void;
export declare function decryptRSA(privateKey: any, encryptedData: ArrayBuffer): Promise<ArrayBuffer>;
//# sourceMappingURL=crypto-browser.d.ts.map
/// <reference types="node" resolution-mode="require"/>
declare global {
    interface Window {
    }
    const window: Window;
    const self: Window;
}
export declare function encryptAES(plaintext: string, key: string): {
    ciphertext: string;
    r: string;
};
export declare function decryptAES(ciphertext: string, key: string, r: string): string;
export declare function generateRSAKeyPair(): Promise<{
    publicKey: any;
    privateKey: any;
}>;
export declare function decryptRSA(ciphertext: ArrayBuffer, privateKey: ArrayBuffer): Promise<ArrayBuffer>;
export declare function decryptValue(ctAmount: bigint, aesKey: string): number;
export declare function signRawMessage(message: string | Buffer, walletSigningKey: string): Buffer;
export declare function prepareMessage(plaintext: bigint, signerAddress: string, aesKey: string, contractAddress: string, functionSelector: string): {
    encryptedInt: bigint;
    messageHash: string;
};
//# sourceMappingURL=crypto-browser.d.ts.map
/// <reference types="node" resolution-mode="require"/>
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
export declare function prepareMessage(plaintext: bigint, signerAddress: string, aesKey: string, contractAddress: string, functionSelector: string): {
    encryptedInt: bigint;
    messageHash: string;
};
export declare function encryptAES(key: string, plaintext: string): {
    ciphertext: string;
    r: string;
};
export declare function signRawMessage(message: string | Buffer, walletSigningKey: string): Buffer;
export declare function decryptRSA(privateKeyData: ArrayBuffer, encryptedData: ArrayBuffer): Promise<ArrayBuffer>;
//# sourceMappingURL=crypto-browser.d.ts.map
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
export declare function decryptRSAMessage(privateKey: any, encryptedData: ArrayBuffer): Promise<ArrayBuffer>;
export declare function importRSAPrivateKey(privateKeyData: ArrayBuffer): Promise<any>;
export declare function sign(message: string, privateKey: string): Buffer;
export declare function decryptValue(ctAmount: bigint, userKey: string): number;
export declare function prepareIT(plaintext: bigint, walletAddress: string, walletPrivateKey: string, userKey: string, contractAddress: string, functionSelector: string): Promise<{
    encryptedSecret: bigint;
    signature: Buffer;
}>;
//# sourceMappingURL=crypto-browser.d.ts.map
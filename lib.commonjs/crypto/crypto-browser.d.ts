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
//# sourceMappingURL=crypto-browser.d.ts.map
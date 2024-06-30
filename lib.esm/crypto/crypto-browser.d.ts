/// <reference types="node" />
declare global {
    interface Window {
    }
    const window: Window;
    const self: Window;
}
/**
 * Encrypts plaintext using AES encryption with the specified key.
 *
 * @param {string} plaintext - The plaintext to be encrypted, represented as a hex string.
 * @param {string} key - The AES encryption key, represented as a hex string. Must be 128 bits (16 bytes).
 * @returns {{ ciphertext: string, r: string }} - An object containing the ciphertext as a hex string and the random value 'r' as a hex string.
 */
export declare function encryptAES(plaintext: string, key: string): {
    ciphertext: string;
    r: string;
};
/**
 * Decrypts ciphertext using AES decryption with the specified key and random value.
 *
 * @param {string} ciphertext - The ciphertext to be decrypted, represented as a hex string.
 * @param {string} key - The AES encryption key, represented as a hex string. Must be 128 bits (16 bytes).
 * @param {string} r - The random value 'r' used for encryption, represented as a hex string. Must be 128 bits (16 bytes).
 * @returns {string} - The decrypted plaintext, represented as a hex string.
 * @throws {RangeError} - If the size of ciphertext, key, or random value 'r' is not 128 bits (16 bytes).
 */
export declare function decryptAES(ciphertext: string, key: string, r: string): string;
/**
 * Generates a new RSA key pair.
 *
 * @returns {Promise<CryptoKeyPair>} - A Promise that resolves to an object containing the generated RSA key pair.
 */
export declare function generateRSAKeyPair(): Promise<{
    publicKey: any;
    privateKey: any;
}>;
/**
 * Decrypts ciphertext using RSA-OAEP with the provided private key.
 *
 * @param {ArrayBuffer} ciphertext - The ciphertext to be decrypted, represented as an ArrayBuffer.
 * @param {ArrayBuffer} privateKey - The private key used for decryption, represented as an ArrayBuffer.
 * @returns {Promise<ArrayBuffer>} - A Promise that resolves to the decrypted plaintext as an ArrayBuffer.
 * @throws {Error} - If decryption fails or if the parameters are not of the expected type.
 */
export declare function decryptRSA(ciphertext: ArrayBuffer, privateKey: ArrayBuffer): Promise<ArrayBuffer>;
/**
 * Decrypts a given ciphertext amount using the specified AES key.
 *
 * @param {bigint} ctAmount - The ciphertext amount to decrypt, represented as a bigint.
 * @param {string} aesKey - The AES key used for decryption, represented as a hex string. The key must be 16, 24, or 32 bytes in length.
 * @returns {number} - The decrypted value as an integer.
 * @throws {TypeError} - If the ctAmount is not a bigint or if the aesKey is not a valid hex string of the correct length.
 */
export declare function decryptValue(ctAmount: bigint, aesKey: string): number;
/**
 * Signs a raw message using the provided wallet signing key.
 *
 * @param {string | Buffer} message - The message to be signed. Must be a non-empty string or Buffer.
 * @param {string} walletSigningKey - The private key used for signing, represented as a 64-character hex string.
 * @returns {Buffer} - A Buffer containing the concatenated signature components (r, s, and v).
 * @throws {TypeError} - If the message is empty or if the walletSigningKey is not a valid 64-character hex string.
 */
export declare function signRawMessage(message: string | Buffer, walletSigningKey: string): Buffer;
/**
 * Prepares an encrypted message and its corresponding hash for a given plaintext and parameters.
 *
 * @param {bigint} plaintext - The plaintext to be encrypted, represented as a bigint.
 * @param {string} signerAddress - The address of the signer, represented as a string. Must be a valid Ethereum address.
 * @param {string} aesKey - The AES key used for encryption, represented as a hex string. Must be 32 bytes in length.
 * @param {string} contractAddress - The address of the contract, represented as a string. Must be a valid Ethereum address.
 * @param {string} functionSelector - The function selector, represented as a hex string. Must be 4 bytes (8 hex characters) prefixed with '0x'.
 * @returns {{encryptedInt: bigint, messageHash: string}} - An object containing the encrypted value as a bigint and the message hash as a string.
 * @throws {TypeError} - If any of the parameters are not of the expected type or format.
 */
export declare function prepareMessage(plaintext: bigint, signerAddress: string, aesKey: string, contractAddress: string, functionSelector: string): {
    encryptedInt: bigint;
    messageHash: string;
};
//# sourceMappingURL=crypto-browser.d.ts.map
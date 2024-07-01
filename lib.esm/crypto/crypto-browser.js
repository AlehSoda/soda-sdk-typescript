import CryptoJS from "crypto-js";
import { ethers } from "ethers";
function getGlobal() {
    if (typeof self !== 'undefined') {
        return self;
    }
    if (typeof window !== 'undefined') {
        return window;
    }
    if (typeof global !== 'undefined') {
        return global;
    }
    throw new Error('unable to locate global object');
}
;
const anyGlobal = getGlobal();
const crypto = anyGlobal.crypto || anyGlobal.msCrypto;
/**
 * Encrypts plaintext using AES encryption with the specified key.
 *
 * @param {string} plaintext - The plaintext to be encrypted, represented as a hex string.
 * @param {string} key - The AES encryption key, represented as a hex string. Must be 128 bits (16 bytes).
 * @returns {{ ciphertext: string, r: string }} - An object containing the ciphertext as a hex string and the random value 'r' as a hex string.
 */
export function encryptAES(plaintext, key) {
    const blockSize = 16; // 128 bits
    const keyBytes = CryptoJS.enc.Hex.parse(key);
    // Generate a random value 'r' of the same length as the block size
    const r = CryptoJS.lib.WordArray.random(blockSize);
    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = CryptoJS.AES.encrypt(r, keyBytes, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintextPadded = CryptoJS.enc.Hex.parse(plaintext.padStart(blockSize * 2, '0'));
    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertextWords = encryptedR.ciphertext.words.map((word, i) => word ^ plaintextPadded.words[i]);
    const ciphertext = CryptoJS.lib.WordArray.create(ciphertextWords).toString(CryptoJS.enc.Hex);
    return { ciphertext, r: r.toString(CryptoJS.enc.Hex) };
}
/**
 * Decrypts ciphertext using AES decryption with the specified key and random value.
 *
 * @param {string} ciphertext - The ciphertext to be decrypted, represented as a hex string.
 * @param {string} key - The AES encryption key, represented as a hex string. Must be 128 bits (16 bytes).
 * @param {string} r - The random value 'r' used for encryption, represented as a hex string. Must be 128 bits (16 bytes).
 * @returns {string} - The decrypted plaintext, represented as a hex string.
 * @throws {RangeError} - If the size of ciphertext, key, or random value 'r' is not 128 bits (16 bytes).
 */
export function decryptAES(ciphertext, key, r) {
    const blockSize = 16; // 128 bits
    const keyBytes = CryptoJS.enc.Hex.parse(key);
    const rBytes = CryptoJS.enc.Hex.parse(r);
    const ciphertextBytes = CryptoJS.enc.Hex.parse(ciphertext);
    if (ciphertextBytes.sigBytes !== blockSize) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }
    if (keyBytes.sigBytes !== blockSize) {
        throw new RangeError("Key size must be 128 bits.");
    }
    if (rBytes.sigBytes !== blockSize) {
        throw new RangeError("Random size must be 128 bits.");
    }
    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = CryptoJS.AES.encrypt(rBytes, keyBytes, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintextWords = encryptedR.ciphertext.words.map((word, i) => word ^ ciphertextBytes.words[i]);
    const plaintext = CryptoJS.lib.WordArray.create(plaintextWords).toString(CryptoJS.enc.Hex);
    return plaintext;
}
/**
 * Generates a new RSA key pair.
 *
 * @returns {Promise<CryptoKeyPair>} - A Promise that resolves to an object containing the generated RSA key pair.
 */
export async function generateRSAKeyPair() {
    // Generate a new RSA key pair
    const keyPair = await crypto.subtle.generateKey({
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: { name: "SHA-256" },
    }, true, ["encrypt", "decrypt"]);
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    return { publicKey, privateKey };
}
/**
 * Decrypts ciphertext using RSA-OAEP with the provided private key.
 *
 * @param {ArrayBuffer} ciphertext - The ciphertext to be decrypted, represented as an ArrayBuffer.
 * @param {ArrayBuffer} privateKey - The private key used for decryption, represented as an ArrayBuffer.
 * @returns {Promise<ArrayBuffer>} - A Promise that resolves to the decrypted plaintext as an ArrayBuffer.
 * @throws {Error} - If decryption fails or if the parameters are not of the expected type.
 */
export async function decryptRSA(ciphertext, privateKey) {
    const importedPrivateKey = await importRSAPrivateKey(privateKey);
    return await crypto.subtle.decrypt({
        name: "RSA-OAEP"
    }, importedPrivateKey, ciphertext);
}
/**
 * Decrypts a given ciphertext amount using the specified AES key.
 *
 * @param {bigint} ctAmount - The ciphertext amount to decrypt, represented as a bigint.
 * @param {string} aesKey - The AES key used for decryption, represented as a hex string. The key must be 16, 24, or 32 bytes in length.
 * @returns {number} - The decrypted value as an integer.
 * @throws {TypeError} - If the ctAmount is not a bigint or if the aesKey is not a valid hex string of the correct length.
 */
export function decryptValue(ctAmount, aesKey) {
    // Validate aesKey (32 bytes as hex string)
    if (typeof aesKey !== "string" || aesKey.length != 32) {
        throw new TypeError("Invalid AES key length. Expected 32 bytes.");
    }
    const blockSize = 16; // 128 bits
    const hexBase = 16;
    // Convert CT to hex string
    let ctString = ctAmount.toString(hexBase);
    let ctArray = CryptoJS.enc.Hex.parse(ctString);
    while (ctArray.sigBytes < 32) {
        // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
        ctString = "0" + ctString;
        ctArray = CryptoJS.enc.Hex.parse(ctString);
    }
    // Split CT into two 128-bit arrays r and cipher
    const cipherHex = ctArray.toString(CryptoJS.enc.Hex).substring(0, blockSize * 2);
    const rHex = ctArray.toString(CryptoJS.enc.Hex).substring(blockSize * 2);
    // Decrypt the cipher
    const decryptedMessageHex = decryptAES(cipherHex, aesKey, rHex);
    return parseInt(decryptedMessageHex, hexBase);
}
/**
 * Signs a raw message using the provided wallet signing key.
 *
 * @param {string | Buffer} message - The message to be signed. Must be a non-empty string or Buffer.
 * @param {string} walletSigningKey - The private key used for signing, represented as a 66-character hex string.
 * @returns {Buffer} - A Buffer containing the concatenated signature components (r, s, and v).
 * @throws {TypeError} - If the message is empty or if the walletSigningKey is not a valid 66-character hex string.
 */
export function signRawMessage(message, walletSigningKey) {
    // Validate message
    if (message.length == 0) {
        throw new TypeError("Message must be a non-empty string or Buffer");
    }
    // Validate walletSigningKey (private key length should be 66 hex characters)
    if (walletSigningKey.length !== 66) {
        throw new TypeError("Invalid wallet signing key length. Expected 66 hex characters.");
    }
    const key = new ethers.SigningKey(walletSigningKey);
    const sig = key.sign(message);
    return Buffer.concat([ethers.getBytes(sig.r), ethers.getBytes(sig.s), ethers.getBytes(`0x0${sig.v - 27}`)]);
}
async function importRSAPrivateKey(privateKeyData) {
    return await crypto.subtle.importKey("pkcs8", privateKeyData, {
        name: "RSA-OAEP",
        hash: { name: "SHA-256" }
    }, true, ["decrypt"]);
}
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
export function prepareMessage(plaintext, signerAddress, aesKey, contractAddress, functionSelector) {
    // Validate signerAddress (Ethereum address)
    if (!ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid signer address");
    }
    // Validate aesKey (32 bytes as hex string)
    if (typeof aesKey !== "string" || aesKey.length != 32) {
        throw new TypeError("Invalid AES key length. Expected 32 bytes.");
    }
    // Validate contractAddress (Ethereum address)
    if (typeof contractAddress !== "string" || !ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid contract address");
    }
    // Validate functionSelector (4 bytes as hex string)
    if (typeof functionSelector !== "string" || functionSelector.length !== 10 || !functionSelector.startsWith('0x')) {
        throw new TypeError("Invalid function selector");
    }
    // Convert the plaintext to a hex string
    const plaintextHex = plaintext.toString(16).padStart(16, '0'); // Ensure it's 8 bytes (16 hex chars)
    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encryptAES(plaintextHex, aesKey);
    const ct = ciphertext + r;
    const messageHash = ethers.solidityPackedKeccak256(["address", "address", "bytes4", "uint256"], [signerAddress, contractAddress, functionSelector, BigInt("0x" + ct)]);
    const encryptedInt = BigInt("0x" + ct);
    return { encryptedInt, messageHash };
}
//# sourceMappingURL=crypto-browser.js.map
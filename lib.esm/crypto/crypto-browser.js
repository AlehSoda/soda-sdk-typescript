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
export function decryptAES(key, r, ciphertext) {
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
export function decryptValue(ctAmount, userKey) {
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
    const decryptedMessageHex = decryptAES(userKey, rHex, cipherHex);
    return parseInt(decryptedMessageHex, hexBase);
}
export function prepareMessage(plaintext, signerAddress, aesKey, contractAddress, functionSelector) {
    // Convert the plaintext to a hex string
    const plaintextHex = plaintext.toString(16).padStart(16, '0'); // Ensure it's 8 bytes (16 hex chars)
    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encryptAES(aesKey, plaintextHex);
    const ct = ciphertext + r;
    const messageHash = ethers.solidityPackedKeccak256(["address", "address", "bytes4", "uint256"], [signerAddress, contractAddress, functionSelector, BigInt("0x" + ct)]);
    const encryptedInt = BigInt("0x" + ct);
    return { encryptedInt, messageHash };
}
export function encryptAES(key, plaintext) {
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
export function signRawMessage(message, walletSigningKey) {
    const key = new ethers.SigningKey(walletSigningKey);
    const sig = key.sign(message);
    return Buffer.concat([ethers.getBytes(sig.r), ethers.getBytes(sig.s), ethers.getBytes(`0x0${sig.v - 27}`)]);
}
export async function decryptRSA(privateKeyData, encryptedData) {
    const importedPrivateKey = await importRSAPrivateKey(privateKeyData);
    return await crypto.subtle.decrypt({
        name: "RSA-OAEP"
    }, importedPrivateKey, encryptedData);
}
async function importRSAPrivateKey(privateKeyData) {
    return await crypto.subtle.importKey("pkcs8", privateKeyData, {
        name: "RSA-OAEP",
        hash: { name: "SHA-256" }
    }, true, ["decrypt"]);
}
//# sourceMappingURL=crypto-browser.js.map
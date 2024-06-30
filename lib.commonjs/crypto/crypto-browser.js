"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prepareMessage = exports.signRawMessage = exports.decryptValue = exports.decryptRSA = exports.generateRSAKeyPair = exports.decryptAES = exports.encryptAES = void 0;
const tslib_1 = require("tslib");
const crypto_js_1 = tslib_1.__importDefault(require("crypto-js"));
const ethers_1 = require("ethers");
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
function encryptAES(plaintext, key) {
    const blockSize = 16; // 128 bits
    const keyBytes = crypto_js_1.default.enc.Hex.parse(key);
    // Generate a random value 'r' of the same length as the block size
    const r = crypto_js_1.default.lib.WordArray.random(blockSize);
    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = crypto_js_1.default.AES.encrypt(r, keyBytes, { mode: crypto_js_1.default.mode.ECB, padding: crypto_js_1.default.pad.NoPadding });
    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintextPadded = crypto_js_1.default.enc.Hex.parse(plaintext.padStart(blockSize * 2, '0'));
    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertextWords = encryptedR.ciphertext.words.map((word, i) => word ^ plaintextPadded.words[i]);
    const ciphertext = crypto_js_1.default.lib.WordArray.create(ciphertextWords).toString(crypto_js_1.default.enc.Hex);
    return { ciphertext, r: r.toString(crypto_js_1.default.enc.Hex) };
}
exports.encryptAES = encryptAES;
function decryptAES(ciphertext, key, r) {
    const blockSize = 16; // 128 bits
    const keyBytes = crypto_js_1.default.enc.Hex.parse(key);
    const rBytes = crypto_js_1.default.enc.Hex.parse(r);
    const ciphertextBytes = crypto_js_1.default.enc.Hex.parse(ciphertext);
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
    const encryptedR = crypto_js_1.default.AES.encrypt(rBytes, keyBytes, { mode: crypto_js_1.default.mode.ECB, padding: crypto_js_1.default.pad.NoPadding });
    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintextWords = encryptedR.ciphertext.words.map((word, i) => word ^ ciphertextBytes.words[i]);
    const plaintext = crypto_js_1.default.lib.WordArray.create(plaintextWords).toString(crypto_js_1.default.enc.Hex);
    return plaintext;
}
exports.decryptAES = decryptAES;
async function generateRSAKeyPair() {
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
exports.generateRSAKeyPair = generateRSAKeyPair;
async function decryptRSA(ciphertext, privateKey) {
    const importedPrivateKey = await importRSAPrivateKey(privateKey);
    return await crypto.subtle.decrypt({
        name: "RSA-OAEP"
    }, importedPrivateKey, ciphertext);
}
exports.decryptRSA = decryptRSA;
function decryptValue(ctAmount, aesKey) {
    const blockSize = 16; // 128 bits
    const hexBase = 16;
    // Convert CT to hex string
    let ctString = ctAmount.toString(hexBase);
    let ctArray = crypto_js_1.default.enc.Hex.parse(ctString);
    while (ctArray.sigBytes < 32) {
        // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
        ctString = "0" + ctString;
        ctArray = crypto_js_1.default.enc.Hex.parse(ctString);
    }
    // Split CT into two 128-bit arrays r and cipher
    const cipherHex = ctArray.toString(crypto_js_1.default.enc.Hex).substring(0, blockSize * 2);
    const rHex = ctArray.toString(crypto_js_1.default.enc.Hex).substring(blockSize * 2);
    // Decrypt the cipher
    const decryptedMessageHex = decryptAES(cipherHex, aesKey, rHex);
    return parseInt(decryptedMessageHex, hexBase);
}
exports.decryptValue = decryptValue;
function signRawMessage(message, walletSigningKey) {
    const key = new ethers_1.ethers.SigningKey(walletSigningKey);
    const sig = key.sign(message);
    return Buffer.concat([ethers_1.ethers.getBytes(sig.r), ethers_1.ethers.getBytes(sig.s), ethers_1.ethers.getBytes(`0x0${sig.v - 27}`)]);
}
exports.signRawMessage = signRawMessage;
async function importRSAPrivateKey(privateKeyData) {
    return await crypto.subtle.importKey("pkcs8", privateKeyData, {
        name: "RSA-OAEP",
        hash: { name: "SHA-256" }
    }, true, ["decrypt"]);
}
function prepareMessage(plaintext, signerAddress, aesKey, contractAddress, functionSelector) {
    // Convert the plaintext to a hex string
    const plaintextHex = plaintext.toString(16).padStart(16, '0'); // Ensure it's 8 bytes (16 hex chars)
    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encryptAES(plaintextHex, aesKey);
    const ct = ciphertext + r;
    const messageHash = ethers_1.ethers.solidityPackedKeccak256(["address", "address", "bytes4", "uint256"], [signerAddress, contractAddress, functionSelector, BigInt("0x" + ct)]);
    const encryptedInt = BigInt("0x" + ct);
    return { encryptedInt, messageHash };
}
exports.prepareMessage = prepareMessage;
//# sourceMappingURL=crypto-browser.js.map
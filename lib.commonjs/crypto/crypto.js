"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prepareMessage = exports.signRawMessage = exports.decryptValue = exports.decryptRSA = exports.generateRSAKeyPair = exports.decryptAES = exports.encryptAES = void 0;
const tslib_1 = require("tslib");
const crypto_1 = tslib_1.__importDefault(require("crypto"));
const ethers_1 = require("ethers");
const block_size = 16; // AES block size in bytes
const hexBase = 16;
function encryptAES(plaintext, key) {
    const plaintextBuf = Buffer.from(plaintext, "hex");
    const keyBuf = Buffer.from(key, "hex");
    // Ensure plaintext is smaller than 128 bits (16 bytes)
    if (plaintextBuf.length > block_size) {
        throw new RangeError("Plaintext size must be 128 bits or smaller.");
    }
    // Ensure key size is 128 bits (16 bytes)
    if (keyBuf.length != block_size) {
        throw new RangeError("Key size must be 128 bits.");
    }
    // Create a new AES cipher using the provided key
    const cipher = crypto_1.default.createCipheriv("aes-128-ecb", keyBuf, null);
    // Generate a random value 'r' of the same length as the block size
    const r = crypto_1.default.randomBytes(block_size);
    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r);
    // Pad the plaintext with zeros if it's smaller than the block size
    const plaintext_padded = Buffer.concat([Buffer.alloc(block_size - plaintext.length), plaintextBuf]);
    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i];
    }
    return { ciphertext, r };
}
exports.encryptAES = encryptAES;
function decryptAES(ciphertext, key, r) {
    if (ciphertext.length !== block_size) {
        throw new RangeError("Ciphertext size must be 128 bits.");
    }
    // Ensure key size is 128 bits (16 bytes)
    if (key.length != block_size) {
        throw new RangeError("Key size must be 128 bits.");
    }
    // Ensure random size is 128 bits (16 bytes)
    if (r.length != block_size) {
        throw new RangeError("Random size must be 128 bits.");
    }
    // Create a new AES decipher using the provided key
    const cipher = crypto_1.default.createCipheriv("aes-128-ecb", key, null);
    // Encrypt the random value 'r' using AES in ECB mode
    const encryptedR = cipher.update(r);
    // XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    const plaintext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        plaintext[i] = encryptedR[i] ^ ciphertext[i];
    }
    return plaintext;
}
exports.decryptAES = decryptAES;
async function generateRSAKeyPair() {
    // Generate a new RSA key pair
    return crypto_1.default.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: "spki",
            format: "der", // Specify 'der' format for binary data
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "der", // Specify 'der' format for binary data
        },
    });
}
exports.generateRSAKeyPair = generateRSAKeyPair;
function decryptRSA(ciphertext, privateKey) {
    // Load the private key in PEM format
    let privateKeyPEM = privateKey.toString("base64");
    privateKeyPEM = `-----BEGIN PRIVATE KEY-----\n${privateKeyPEM}\n-----END PRIVATE KEY-----`;
    // Decrypt the ciphertext using RSA-OAEP
    return crypto_1.default.privateDecrypt({
        key: privateKeyPEM,
        padding: crypto_1.default.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, ciphertext);
}
exports.decryptRSA = decryptRSA;
function decryptValue(ctAmount, aesKey) {
    // Convert CT to bytes
    let ctString = ctAmount.toString(hexBase);
    let ctArray = Buffer.from(ctString, "hex");
    while (ctArray.length < 32) {
        // When the first bits are 0, bigint bit size is less than 32 and need to re-add the bits
        ctString = "0" + ctString;
        ctArray = Buffer.from(ctString, "hex");
    }
    // Split CT into two 128-bit arrays r and cipher
    const cipher = ctArray.subarray(0, block_size);
    const r = ctArray.subarray(block_size);
    // Decrypt the cipher
    const decryptedMessage = decryptAES(cipher, Buffer.from(aesKey, "hex"), r);
    return parseInt(decryptedMessage.toString("hex"), block_size);
}
exports.decryptValue = decryptValue;
function signRawMessage(message, walletSigningKey) {
    const signingKey = new ethers_1.ethers.SigningKey(walletSigningKey);
    const sig = signingKey.sign(message);
    return Buffer.concat([ethers_1.ethers.getBytes(sig.r), ethers_1.ethers.getBytes(sig.s), ethers_1.ethers.getBytes(`0x0${sig.v - 27}`)]);
}
exports.signRawMessage = signRawMessage;
function prepareMessage(plaintext, signerAddress, aesKey, contractAddress, functionSelector) {
    // Convert the plaintext to bytes
    const plaintextBytes = Buffer.alloc(8); // Allocate a buffer of size 8 bytes
    plaintextBytes.writeBigUInt64BE(plaintext); // Write the uint64 value to the buffer as little-endian
    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encryptAES(plaintextBytes.toString("hex"), aesKey);
    const ct = Buffer.concat([ciphertext, r]);
    const messageHash = ethers_1.ethers.solidityPackedKeccak256(["address", "address", "bytes4", "uint256"], [signerAddress, contractAddress, functionSelector, BigInt("0x" + ct.toString("hex"))]);
    // Convert the ciphertext to BigInt
    const encryptedInt = BigInt("0x" + ct.toString("hex"));
    return { encryptedInt, messageHash };
}
exports.prepareMessage = prepareMessage;
//# sourceMappingURL=crypto.js.map
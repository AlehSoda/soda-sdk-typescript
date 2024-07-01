"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prepareMessage = exports.signRawMessage = exports.decryptValue = exports.decryptRSA = exports.generateRSAKeyPair = exports.decryptAES = exports.encryptAES = void 0;
const tslib_1 = require("tslib");
const crypto_1 = tslib_1.__importDefault(require("crypto"));
const ethers_1 = require("ethers");
const block_size = 16; // AES block size in bytes
const hexBase = 16;
/**
 * Encrypts plaintext using AES encryption with the specified key.
 *
 * @param {string} plaintext - The plaintext to be encrypted, represented as a hex string.
 * @param {string} key - The AES encryption key, represented as a hex string. Must be 128 bits (16 bytes).
 * @returns {{ ciphertext: Buffer, r: Buffer }} - An object containing the ciphertext as a Buffer and the random value 'r' as a Buffer.
 * @throws {RangeError} - If the size of plaintext or key is not 128 bits (16 bytes).
 */
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
    const plaintext_padded = Buffer.concat([Buffer.alloc(block_size - plaintextBuf.length), plaintextBuf]);
    // XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    const ciphertext = Buffer.alloc(encryptedR.length);
    for (let i = 0; i < encryptedR.length; i++) {
        ciphertext[i] = encryptedR[i] ^ plaintext_padded[i];
    }
    return { ciphertext, r };
}
exports.encryptAES = encryptAES;
/**
 * Decrypts ciphertext using AES decryption with the specified key and random value.
 *
 * @param {Buffer} ciphertext - The ciphertext to be decrypted, represented as a Buffer.
 * @param {Buffer} key - The AES encryption key, represented as a Buffer. Must be 128 bits (16 bytes).
 * @param {Buffer} r - The random value 'r' used for encryption, represented as a Buffer. Must be 128 bits (16 bytes).
 * @returns {Buffer} - The decrypted plaintext, represented as a Buffer.
 * @throws {RangeError} - If the size of ciphertext, key, or random value 'r' is not 128 bits (16 bytes).
 */
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
/**
 * Generates a new RSA key pair.
 *
 * @returns {Promise<CryptoKeyPair>} - A Promise that resolves to an object containing the generated RSA key pair.
 */
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
/**
 * Decrypts ciphertext using RSA-OAEP with the provided private key.
 *
 * @param {ArrayBuffer} ciphertext - The ciphertext to be decrypted, represented as an ArrayBuffer.
 * @param {ArrayBuffer} privateKey - The private key used for decryption, represented as an ArrayBuffer.
 * @returns {Promise<ArrayBuffer>} - A Promise that resolves to the decrypted plaintext as an ArrayBuffer.
 * @throws {Error} - If decryption fails or if the parameters are not of the expected type.
 */
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
/**
 * Decrypts a given ciphertext amount using the specified AES key.
 *
 * @param {bigint} ctAmount - The ciphertext amount to decrypt, represented as a bigint.
 * @param {string} aesKey - The AES key used for decryption, represented as a hex string. The key must be 16, 24, or 32 bytes in length.
 * @returns {number} - The decrypted value as an integer.
 * @throws {TypeError} - If the ctAmount is not a bigint or if the aesKey is not a valid hex string of the correct length.
 */
function decryptValue(ctAmount, aesKey) {
    // Validate aesKey (32 bytes as hex string)
    if (typeof aesKey !== "string" || aesKey.length != 32) {
        throw new TypeError("Invalid AES key length. Expected 32 bytes.");
    }
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
/**
 * Signs a raw message using the provided wallet signing key.
 *
 * @param {string | Buffer} message - The message to be signed. Must be a non-empty string or Buffer.
 * @param {string} walletSigningKey - The private key used for signing, represented as a 66-character hex string.
 * @returns {Buffer} - A Buffer containing the concatenated signature components (r, s, and v).
 * @throws {TypeError} - If the message is empty or if the walletSigningKey is not a valid 66-character hex string.
 */
function signRawMessage(message, walletSigningKey) {
    // Validate message
    if (message.length == 0) {
        throw new TypeError("Message must be a non-empty string or Buffer");
    }
    // Validate walletSigningKey (private key length should be 66 hex characters)
    if (walletSigningKey.length !== 66) {
        throw new TypeError(`Invalid wallet signing key length. Expected 66 hex characters. Received ${walletSigningKey.length}`);
    }
    const signingKey = new ethers_1.ethers.SigningKey(walletSigningKey);
    const sig = signingKey.sign(message);
    return Buffer.concat([ethers_1.ethers.getBytes(sig.r), ethers_1.ethers.getBytes(sig.s), ethers_1.ethers.getBytes(`0x0${sig.v - 27}`)]);
}
exports.signRawMessage = signRawMessage;
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
function prepareMessage(plaintext, signerAddress, aesKey, contractAddress, functionSelector) {
    // Validate signerAddress (Ethereum address)
    if (!ethers_1.ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid signer address");
    }
    // Validate aesKey (32 bytes as hex string)
    if (typeof aesKey !== "string" || aesKey.length != 32) {
        throw new TypeError("Invalid AES key length. Expected 32 bytes.");
    }
    // Validate contractAddress (Ethereum address)
    if (typeof contractAddress !== "string" || !ethers_1.ethers.isAddress(signerAddress)) {
        throw new TypeError("Invalid contract address");
    }
    // Validate functionSelector (4 bytes as hex string)
    if (typeof functionSelector !== "string" || functionSelector.length !== 10 || !functionSelector.startsWith('0x')) {
        throw new TypeError("Invalid function selector");
    }
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
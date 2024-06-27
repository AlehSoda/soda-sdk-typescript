import {getBytes, SigningKey, solidityPackedKeccak256} from "ethers";

declare global {
    interface Window { }

    const window: Window;
    const self: Window;
}


function getGlobal(): any {
  if (typeof self !== 'undefined') { return self; }
  if (typeof window !== 'undefined') { return window; }
  if (typeof global !== 'undefined') { return global; }
  throw new Error('unable to locate global object');
};

const anyGlobal = getGlobal();
const crypto: any = anyGlobal.crypto || anyGlobal.msCrypto;

export async function generateRSAKeyPair() {
  console.log("From bro");
  // Generate a new RSA key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // Equivalent to 65537
      hash: {name: "SHA-256"},
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  return {publicKey, privateKey};

}

export async function decryptRSAMessage(privateKey: any, encryptedData: ArrayBuffer): Promise<ArrayBuffer> {
    return await crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        privateKey,
        encryptedData
    );
}

export async function importRSAPrivateKey(privateKeyData: ArrayBuffer): Promise<any> {
    return await crypto.subtle.importKey(
        "pkcs8",
        privateKeyData,
        {
            name: "RSA-OAEP",
            hash: { name: "SHA-256" }
        },
        true,
        ["decrypt"]
    );
}

export function sign(message: string, privateKey: string) {
  const key = new SigningKey(privateKey);
  const sig = key.sign(message);
  return Buffer.concat([getBytes(sig.r), getBytes(sig.s), getBytes(`0x0${sig.v - 27}`)]);
}


function encryptWithAESKey(key: string, plaintext: string): { ciphertext: string, r: string } {
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

// AES-128-ECB Decryption
function decryptWithAESKey(key: string, r: string, ciphertext: string): string {
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

export function decryptValue(ctAmount: bigint, userKey: string): number {
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
    const decryptedMessageHex = decryptWithAESKey(userKey, rHex, cipherHex);

    return parseInt(decryptedMessageHex, hexBase);
}

export async function prepareIT(
    plaintext: bigint,
    walletAddress: string,
    walletPrivateKey: string,
    userKey: string,
    contractAddress: string,
    functionSelector: string,
) {
    // Convert the plaintext to a hex string
    const plaintextHex = plaintext.toString(16).padStart(16, '0'); // Ensure it's 8 bytes (16 hex chars)

    // Encrypt the plaintext using AES key
    const { ciphertext, r } = encryptWithAESKey(userKey, plaintextHex);
    const ct = ciphertext + r;
    const message = solidityPackedKeccak256(
        ["address", "address", "bytes4", "uint256"],
        [walletAddress, contractAddress, functionSelector, BigInt("0x" + ct)],
    );

    const signature = sign(message, walletPrivateKey);

    // Convert the ciphertext to BigInt
    const ctInt = BigInt("0x" + ct);

    return { encryptedSecret: ctInt, signature};
}
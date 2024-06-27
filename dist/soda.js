const __$G = (typeof globalThis !== 'undefined' ? globalThis: typeof window !== 'undefined' ? window: typeof global !== 'undefined' ? global: typeof self !== 'undefined' ? self: {});
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
const anyGlobal = getGlobal();
const crypto = anyGlobal.crypto || anyGlobal.msCrypto;
async function generateRSAKeyPair() {
    console.log("From bro");
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

/////////////////////////////
// Types
// export type { ProgressCallback, SignatureLike } from "./crypto/index.js";
// dummy change; to pick-up ws security issue changes

var soda = /*#__PURE__*/Object.freeze({
    __proto__: null,
    generateRSAKeyPair: generateRSAKeyPair
});

export { generateRSAKeyPair, soda };
//# sourceMappingURL=soda.js.map

const __$G = (typeof globalThis !== 'undefined' ? globalThis: typeof window !== 'undefined' ? window: typeof global !== 'undefined' ? global: typeof self !== 'undefined' ? self: {});
(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('crypto-js')) :
    typeof define === 'function' && define.amd ? define(['exports', 'crypto-js'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.soda = {}));
})(this, (function (exports) { 'use strict';

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
    // async function importRSAPrivateKey(privateKeyData: ArrayBuffer): Promise<any> {
    //     return await crypto.subtle.importKey(
    //         "pkcs8",
    //         privateKeyData,
    //         {
    //             name: "RSA-OAEP",
    //             hash: { name: "SHA-256" }
    //         },
    //         true,
    //         ["decrypt"]
    //     );
    // }

    /////////////////////////////
    // Types
    // export type { ProgressCallback, SignatureLike } from "./crypto/index.js";
    // dummy change; to pick-up ws security issue changes

    var soda = /*#__PURE__*/Object.freeze({
        __proto__: null,
        generateRSAKeyPair: generateRSAKeyPair
    });

    exports.generateRSAKeyPair = generateRSAKeyPair;
    exports.soda = soda;

}));
//# sourceMappingURL=soda.umd.js.map

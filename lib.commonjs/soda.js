"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ONBOARDING_CONTRACT_ABI = exports.ONBOARDING_CONTRACT_DEVNET_ADDRESS = exports.signRawMessage = exports.prepareMessage = exports.decryptRSA = exports.decryptValue = exports.decryptAES = exports.encryptAES = exports.generateRSAKeyPair = void 0;
var index_js_1 = require("./crypto/index.js");
Object.defineProperty(exports, "generateRSAKeyPair", { enumerable: true, get: function () { return index_js_1.generateRSAKeyPair; } });
Object.defineProperty(exports, "encryptAES", { enumerable: true, get: function () { return index_js_1.encryptAES; } });
Object.defineProperty(exports, "decryptAES", { enumerable: true, get: function () { return index_js_1.decryptAES; } });
Object.defineProperty(exports, "decryptValue", { enumerable: true, get: function () { return index_js_1.decryptValue; } });
Object.defineProperty(exports, "decryptRSA", { enumerable: true, get: function () { return index_js_1.decryptRSA; } });
Object.defineProperty(exports, "prepareMessage", { enumerable: true, get: function () { return index_js_1.prepareMessage; } });
Object.defineProperty(exports, "signRawMessage", { enumerable: true, get: function () { return index_js_1.signRawMessage; } });
exports.ONBOARDING_CONTRACT_DEVNET_ADDRESS = "0xa7fdb3DeC5054E1ad1D678F9e9E88d03F94DA8f8";
exports.ONBOARDING_CONTRACT_ABI = [
    "function getUserKey(bytes signedEK, bytes signature) public",
    "event UserKey(address indexed _owner, bytes _userKey)"
];
//# sourceMappingURL=soda.js.map
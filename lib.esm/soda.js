export { generateRSAKeyPair, encryptAES, decryptAES, decryptValue, decryptRSA, prepareMessage, signRawMessage } from "./crypto/index.js";
export const ONBOARDING_CONTRACT_DEVNET_ADDRESS = "0xa7fdb3DeC5054E1ad1D678F9e9E88d03F94DA8f8";
export const ONBOARDING_CONTRACT_ABI = [
    "function getUserKey(bytes signedEK, bytes signature) public",
    "event UserKey(address indexed _owner, bytes _userKey)"
];
//# sourceMappingURL=soda.js.map
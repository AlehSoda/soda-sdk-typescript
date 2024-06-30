export {
  generateRSAKeyPair,
  encryptAES,
  decryptAES,
  decryptValue,
  decryptRSA,
  prepareMessage,
  signRawMessage
} from "./crypto/index.js";

export const ONBOARDING_CONTRACT_DEVNET_ADDRESS = "0xE7Bc1a2A2633A1fA4E361f98C4841Cc3c58B94CD"
export const ONBOARDING_CONTRACT_ABI = [
  "function getUserKey(bytes signedEK, bytes signature) public",
  "event UserKey(address indexed _owner, bytes _userKey)"
];

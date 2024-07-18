export {
  generateRSAKeyPair,
  encryptAES,
  decryptAES,
  decryptValue,
  decryptRSA,
  prepareMessage,
  signRawMessage
} from "./crypto/index.js";

export const ONBOARDING_CONTRACT_DEVNET_ADDRESS = "0xBaeC693DEE087dD1aD212640897EcD2f6510991f"
export const ONBOARDING_CONTRACT_ABI = [
  "function getUserKey(bytes signedEK, bytes signature) public",
  "event UserKey(address indexed _owner, bytes _userKey)"
];

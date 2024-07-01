# Soda SDK typescript

This SDK provides a suite of cryptographic functions for working with a privacy-oriented blockchain. It supports both Node.js and browser environments and includes utilities for AES encryption/decryption, RSA key generation and decryption, and message signing.

## Installation

You can install the SDK using npm:

```bash
npm install https://github.com/AlehSoda/soda-sdk-typescript.git
```

## Importing the SDK

In a Node.js environment, you can import the SDK as follows:

```typescript

import { soda } from "soda-sdk";

```

## Onboarding (getting AES user key) example in the browser using devnet

```typescript
import { soda } from "soda-sdk";
import { ethers } from "ethers";

const provider =  new ethers.JsonRpcProvider('https://node.sodalabs.net')
const wallet = ethers.Wallet.createRandom(provider);
const {publicKey, privateKey} = await soda.generateRSAKeyPair();
const publicKeyHash = ethers.keccak256(new Uint8Array(publicKey));
// Singing publicKeyHash with wallet private key
const signedRSAPublicKey = soda.signRawMessage(publicKeyHash, wallet.privateKey);
// connecting to onboarding contract
const contract = new ethers.Contract(soda.ONBOARDING_CONTRACT_DEVNET_ADDRESS, soda.ONBOARDING_CONTRACT_ABI, wallet);
// calling getUserKey function with publicKey and signedRSAPublicKey
const tx = await contract.getUserKey(new Uint8Array(publicKey), signedRSAPublicKey, {gasLimit: 12000000})
const receipt = await (tx).wait();
// parsing log to get encrypted AES key
const decodedLog = contract.interface.parseLog(receipt.logs[0]);
const encryptedAESKey = decodedLog.args._userKey;
// decrypting AES key with RSA private key
const decryptedAesKeyBytes = await soda.decryptRSA(toBytes(encryptedAESKey), privateKey)
const decryptedAesKey = fromBytes(new Uint8Array(decryptedAesKeyBytes), "hex")
console.log("decryptedAesKey:", decryptedAesKey) 
```

## Calling smart contract with encrypted values example in the browser

```typescript
import { soda } from "soda-sdk";
import { ethers } from "ethers";

const wallet = ethers.Wallet.createRandom(provider);
const aesKey = new Uint8Array(32);
const contract = new ethers.Contract(...);
const func = contract.connect(wallet).functionName;
const plainText = 1n;

const {encryptedInt, messageHash} = soda.prepareMessage(plainText, wallet.address, aesKey, await contract.getAddress(), func.fragment.selector)
const signature = soda.signRawMessage(messageHash, wallet.privateKey);
const tx = await func(encryptedInt, signature, {gasLimit: 12000000});
const receipt = await (tx).wait();
```

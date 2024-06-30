import {prepareMessage} from "../soda";
import {ethers} from "ethers";

describe("Test Soda SDK functions", function () {

  it("Prepare message", function () {
    const plainText = BigInt(1);
    const signingKey = "0xc8809137a42118c8da4ce187de36186790b03ecf002ebe424a1e08846fc6b7d2";
    const wallet = new ethers.Wallet(signingKey);
    const aesKey = "4766255d3eac2d1e85b414dd8cc9bdda";
    const contractAddress = "0xd19356256604E5832C8cAc3eb3Eef4A6f5A67164"
    const functionSelector = "0xecf6f982"
    const prepared = prepareMessage(plainText, wallet.address, aesKey, contractAddress, functionSelector);
    console.assert(prepared.encryptedInt);
    console.assert(prepared.messageHash);
  });
});
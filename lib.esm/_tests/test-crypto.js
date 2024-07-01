import { prepareMessage, signRawMessage } from "../index.js";
import { ethers } from "ethers";
import { expect } from "chai";
describe("Test Soda SDK functions", function () {
    it("Prepare message", function () {
        const plainText = BigInt(1);
        const signingKey = "0xc8809137a42118c8da4ce187de36186790b03ecf002ebe424a1e08846fc6b7d2";
        const wallet = new ethers.Wallet(signingKey);
        const aesKey = "4766255d3eac2d1e85b414dd8cc9bdda";
        const contractAddress = "0xd19356256604E5832C8cAc3eb3Eef4A6f5A67164";
        const functionSelector = "0xecf6f982";
        const prepared = prepareMessage(plainText, wallet.address, aesKey, contractAddress, functionSelector);
        expect(prepared.encryptedInt.toString()).is.not.empty;
        expect(prepared.messageHash.toString()).is.not.empty;
    });
    it("Sign raw message", function () {
        const signingKey = "0xc8809137a42118c8da4ce187de36186790b03ecf002ebe424a1e08846fc6b7d2";
        const messageHash = '0x9f96c05a7cd54a5bba565878aaf49a95ecfe9f8f5d0e0850e6da9a1190ad8a51';
        const signature = signRawMessage(messageHash, signingKey);
        const expectedSignature = "33f6f93597811d61579137df155208a520b11b6567b0049f4406be37936e50ec070eaa977f7441bf630fa74487909994933f6c6c5f05f224f7d876dd9761acd900";
        expect(signature.toString('hex')).is.equal(expectedSignature);
    });
});
//# sourceMappingURL=test-crypto.js.map
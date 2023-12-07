// SPDX-License-Identifier: GPL-3.0-or-later
// adpated from https://github.com/daimo-eth/daimo/blob/master/packages/contract/test/Utils.sol
pragma solidity ^0.8.13;

import "../src/ERC4337Account.sol";
import "p256-verifier/src/utils/Base64URL.sol";

library Utils {
    function rawSignatureToSignature(
        bytes memory challenge,
        uint256 r,
        uint256 s, 
        uint8 ownerIndex
    ) public pure returns (ERC4337Account.PasskeySignature memory) {
        string memory challengeb64url = Base64URL.encode(challenge);
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                challengeb64url,
                '","origin":"https://daimo.xyz"}'
            )
        );

        bytes memory authenticatorData = new bytes(37);
        authenticatorData[32] = bytes1(0x05); // flags: user present, user verified

        return
            ERC4337Account.PasskeySignature({
                authenticatorData: authenticatorData,
                clientDataJSON: clientDataJSON,
                r: r,
                s: s,
                ownerIndex: ownerIndex
            });
    }
}

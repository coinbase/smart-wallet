// SPDX-License-Identifier: GPL-3.0-or-later
// adpated from https://github.com/daimo-eth/daimo/blob/master/packages/contract/test/Utils.sol
pragma solidity ^0.8.0;

import "../src/ERC4337Account.sol";
import "p256-verifier/src/utils/Base64URL.sol";

struct WebAuthnInfo {
        bytes authenticatorData;
        string clientDataJSON;
        bytes32 messageHash;
    }

library Utils {
    function getWebAuthnStruct(bytes32 challenge)
        public
        pure
        returns (WebAuthnInfo memory)
    {
        string memory challengeb64url = Base64URL.encode(abi.encode(challenge));
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                challengeb64url,
                '","origin":"http://localhost:3001","crossOrigin":false}'
            )
        );

        // Authenticator data for Chrome Profile touchID signature
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        bytes32 messageHash = sha256(
            abi.encodePacked(authenticatorData, clientDataJSONHash)
        );

        return WebAuthnInfo(authenticatorData, clientDataJSON, messageHash);
    }
}

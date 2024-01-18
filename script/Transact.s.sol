// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";

import {ERC4337Factory, ERC4337Account} from "../src/ERC4337Factory.sol";
import {IEntryPoint, UserOperation} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "../test/Utils.sol";

import "p256-verifier/src/P256.sol";

contract TransactScript is Script {
    ERC4337Factory f = ERC4337Factory(0x748e5dD94d5F619371d763adfcBB0eDB863905fD);
    uint256 passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    bytes passkeyOwner =
        hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d";
    bytes[] owners;
    uint256 deployerPrivateKey;
    IEntryPoint entryPoint = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
    ERC4337Account account = ERC4337Account(payable(0xDCeE0dF9513eb53a55E9dE7bBc93A04F8DABd3F4));

    // function setUp() public {
    //   ;
    // }

    function run() public {
      deployerPrivateKey = vm.envUint("PRIVATE_KEY");
      vm.startBroadcast(deployerPrivateKey);
      console2.logBytes(account.ownerAtIndex(1));
        // owners.push(abi.encode(vm.addr(deployerPrivateKey)));
        // owners.push(passkeyOwner);
        // account = ERC4337Account(payable(f.createAccount(owners, 1)));
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: uint256(1_200_000),
            verificationGasLimit: uint256(1_200_000),
            preVerificationGas: uint256(1_002_600),
            maxFeePerGas: uint256(0),
            maxPriorityFeePerGas: uint256(0),
            paymasterAndData: "",
            signature: ""
        });
        console2.log(userOp.sender);
        bytes32 challenge = entryPoint.getUserOpHash(userOp);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);
        console2.logBytes32(challenge);
        console2.log(passkeyPrivateKey);
        console2.log('message hash');
        console2.logBytes32(webAuthn.messageHash);
        bytes32 check = webAuthn.messageHash;
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, 0x42c6f69fda4041cf88c936eda008c305d538aa4c2fb85b8bf444b29c144f4014);
        (uint x, uint y) = abi.decode(passkeyOwner, (uint, uint));
        console2.log('woah');
        console2.log(P256.verifySignature(0x42c6f69fda4041cf88c936eda008c305d538aa4c2fb85b8bf444b29c144f4014, uint256(r), uint256(s), x, y));

        ERC4337Account.PasskeySignature memory sig = 
            ERC4337Account.PasskeySignature({
                authenticatorData: webAuthn.authenticatorData,
                clientDataJSON: webAuthn.clientDataJSON,
                r: uint256(r),
                s: uint256(s)
            });

        bytes memory sigWithOwnerIndex = abi.encodePacked(uint8(1), abi.encode(sig));
        userOp.signature = sigWithOwnerIndex; 
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        console2.log(account.verifySignature(challenge, sig, x, y));
        console2.log(WebAuthn2.verifySignature({
          challenge: abi.encode(challenge),
          authenticatorData: webAuthn.authenticatorData,
          clientDataJSON: webAuthn.clientDataJSON,
          requireUserVerification: false,
          challengeLocation: 23,
          responseTypeLocation: 1,
          r: uint(r),
          s: uint(s),
          x: x,
          y: y


        }));
        console2.log(P256.verifySignature(webAuthn.messageHash, uint256(r), uint256(s), x, y));
        
        entryPoint.handleOps(ops, payable(vm.addr(deployerPrivateKey)));
    }
}

library WebAuthn2 {
    /// Checks whether substr occurs in str starting at a given byte offset.
    function contains(
        string memory substr,
        string memory str,
        uint256 location
    ) internal pure returns (bool) {
        bytes memory substrBytes = bytes(substr);
        bytes memory strBytes = bytes(str);

        uint256 substrLen = substrBytes.length;
        uint256 strLen = strBytes.length;

        for (uint256 i = 0; i < substrLen; i++) {
            if (location + i >= strLen) {
                return false;
            }

            if (substrBytes[i] != strBytes[location + i]) {
                return false;
            }
        }

        return true;
    }

    bytes1 constant AUTH_DATA_FLAGS_UP = 0x01; // Bit 0
    bytes1 constant AUTH_DATA_FLAGS_UV = 0x04; // Bit 2
    bytes1 constant AUTH_DATA_FLAGS_BE = 0x08; // Bit 3
    bytes1 constant AUTH_DATA_FLAGS_BS = 0x10; // Bit 4

    /// Verifies the authFlags in authenticatorData. Numbers in inline comment
    /// correspond to the same numbered bullets in
    /// https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
    function checkAuthFlags(
        bytes1 flags,
        bool requireUserVerification
    ) internal pure returns (bool) {
        // 17. Verify that the UP bit of the flags in authData is set.
        if (flags & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
            return false;
        }

        // 18. If user verification was determined to be required, verify that
        // the UV bit of the flags in authData is set. Otherwise, ignore the
        // value of the UV flag.
        if (
            requireUserVerification &&
            (flags & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV
        ) {
            return false;
        }

        // 19. If the BE bit of the flags in authData is not set, verify that
        // the BS bit is not set.
        if (flags & AUTH_DATA_FLAGS_BE != AUTH_DATA_FLAGS_BE) {
            if (flags & AUTH_DATA_FLAGS_BS == AUTH_DATA_FLAGS_BS) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verifies a Webauthn P256 signature (Authentication Assertion) as described
     * in https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion. We do not
     * verify all the steps as described in the specification, only ones relevant
     * to our context. Please carefully read through this list before usage.
     * Specifically, we do verify the following:
     * - Verify that authenticatorData (which comes from the authenticator,
     *   such as iCloud Keychain) indicates a well-formed assertion. If
     *   requireUserVerification is set, checks that the authenticator enforced
     *   user verification. User verification should be required if,
     *   and only if, options.userVerification is set to required in the request
     * - Verifies that the client JSON is of type "webauthn.get", i.e. the client
     *   was responding to a request to assert authentication.
     * - Verifies that the client JSON contains the requested challenge.
     * - Finally, verifies that (r, s) constitute a valid signature over both
     *   the authenicatorData and client JSON, for public key (x, y).
     *
     * We make some assumptions about the particular use case of this verifier,
     * so we do NOT verify the following:
     * - Does NOT verify that the origin in the clientDataJSON matches the
     *   Relying Party's origin: It is considered the authenticator's
     *   responsibility to ensure that the user is interacting with the correct
     *   RP. This is enforced by most high quality authenticators properly,
     *   particularly the iCloud Keychain and Google Password Manager were
     *   tested.
     * - Does NOT verify That c.topOrigin is well-formed: We assume c.topOrigin
     *   would never be present, i.e. the credentials are never used in a
     *   cross-origin/iframe context. The website/app set up should disallow
     *   cross-origin usage of the credentials. This is the default behaviour for
     *   created credentials in common settings.
     * - Does NOT verify that the rpIdHash in authData is the SHA-256 hash of an
     *   RP ID expected by the Relying Party: This means that we rely on the
     *   authenticator to properly enforce credentials to be used only by the
     *   correct RP. This is generally enforced with features like Apple App Site
     *   Association and Google Asset Links. To protect from edge cases in which
     *   a previously-linked RP ID is removed from the authorised RP IDs,
     *   we recommend that messages signed by the authenticator include some
     *   expiry mechanism.
     * - Does NOT verify the credential backup state: This assumes the credential
     *   backup state is NOT used as part of Relying Party business logic or
     *   policy.
     * - Does NOT verify the values of the client extension outputs: This assumes
     *   that the Relying Party does not use client extension outputs.
     * - Does NOT verify the signature counter: Signature counters are intended
     *   to enable risk scoring for the Relying Party. This assumes risk scoring
     *   is not used as part of Relying Party business logic or policy.
     * - Does NOT verify the attestation object: This assumes that
     *   response.attestationObject is NOT present in the response, i.e. the
     *   RP does not intend to verify an attestation.
     */
    function verifySignature(
        bytes memory challenge,
        bytes memory authenticatorData,
        bool requireUserVerification,
        string memory clientDataJSON,
        uint256 challengeLocation,
        uint256 responseTypeLocation,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        // Check that authenticatorData has good flags
        if (
            authenticatorData.length < 37 ||
            !checkAuthFlags(authenticatorData[32], requireUserVerification)
        ) {
          console2.log("1");
            return false;
        }

        // Check that response is for an authentication assertion
        string memory responseType = '"type":"webauthn.get"';
        if (!contains(responseType, clientDataJSON, responseTypeLocation)) {
        console2.log("2");
            return false;
        }

        // Check that challenge is in the clientDataJSON
        string memory challengeB64url = Base64URL.encode(challenge);
        string memory challengeProperty = string.concat(
            '"challenge":"',
            challengeB64url,
            '"'
        );

        if (!contains(challengeProperty, clientDataJSON, challengeLocation)) {
          console2.log("3");
            return false;
        }

        // Check that the public key signed sha256(authenticatorData || sha256(clientDataJSON))
        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        bytes32 messageHash = sha256(
            abi.encodePacked(authenticatorData, clientDataJSONHash)
        );

        console2.log('message hash');
        console2.logBytes32( messageHash);
        return P256.verifySignature(messageHash, r, s, x, y);
    }
}


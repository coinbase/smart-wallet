// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

// TODO check apache license
import {Base64Url} from "FreshCryptoLib/utils/Base64Url.sol";
import "p256-verifier/src/P256.sol";

/// @notice Helper library for external contracts to verify WebAuthn signatures.
/// @author Wilson Cusack
/// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
library WebAuthn {
    struct WebAuthnAuth {
        /// @dev https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata
        bytes authenticatorData;
        /// @dev https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-origin
        string origin;
        /// @dev https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-crossorigin
        bool crossOrigin;
        /// @dev 13. https://www.w3.org/TR/webauthn/#clientdatajson-serialization
        /// e.g. '"tokenBinding":{"status":"present","id":"TbId"}'
        string remainder;
        /// @dev The r value of secp256r1 signature
        uint256 r;
        /// @dev The r value of secp256r1 signature
        uint256 s;
    }

    /// @dev Bit 0, User present bit in authenticatorData
    bytes1 constant AUTH_DATA_FLAGS_UP = 0x01;
    /// @dev Bit 2, User verified bit in authenticatorData
    bytes1 constant AUTH_DATA_FLAGS_UV = 0x04;
    /// @dev secp256r1 curve order / 2 for malleability check
    uint256 constant P256_N_DIV_2 = 57896044605178124381348723474703786764998477612067880171211129530534256022184;
    address constant VERIFIER = address(0x100);

    /**
     * Verifies a Webauthn P256 signature (Authentication Assertion) as described
     * in https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion. We do not
     * verify all the steps as described in the specification, only ones relevant
     * to our context. Please carefully read through this list before usage.
     * Specifically, we do verify the following:
     * - Verify that authenticatorData (which comes from the authenticator,
     *   such as iCloud Keychain) indicates a well-formed assertion with the user present bit set.
     *   If requireUserVerification is set, checks that the authenticator enforced
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
    function verify(
        bytes memory challenge,
        bool requireUserVerification,
        WebAuthnAuth memory webAuthnAuth,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        if (webAuthnAuth.s > P256_N_DIV_2) {
            // guard against signature malleability
            return false;
        }

        // 11. and 12. will be verified by the signature check
        // 11. Verify that the value of C.type is the string webauthn.get.
        // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        string memory challengeB64url = Base64Url.encode(challenge);
        string memory remainder =
            bytes(webAuthnAuth.remainder).length == 0 ? "" : string.concat(",", webAuthnAuth.remainder);
        string memory clientDataJSON = string.concat(
            // A well formed clientDataJSON will always begin with
            // {"type":"webauthn.get","challenge":"
            // and so we can save calldata and use this by default
            // https://www.w3.org/TR/webauthn/#clientdatajson-serialization
            '{"type":"webauthn.get","challenge":"',
            challengeB64url,
            '",',
            '"origin":"',
            webAuthnAuth.origin,
            '",',
            '"crossOrigin":',
            webAuthnAuth.crossOrigin ? "true" : "false",
            remainder,
            "}"
        );

        // Skip 13., 14., and 15.

        // 16. Verify that the User Present bit of the flags in authData is set.
        if (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
            return false;
        }

        // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
        if (requireUserVerification && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV)
        {
            return false;
        }

        // skip 18.

        // 19. Let hash be the result of computing a hash over the cData using SHA-256.
        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));

        // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
        bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash));
        bytes memory args = abi.encode(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
        // try the RIP-7212 precompile address
        (, bytes memory ret) = VERIFIER.staticcall(args);
        // staticcall will not revert if address has no code
        // check return length
        bool valid = ret.length > 0;
        if (valid) return abi.decode(ret, (uint256)) == 1;

        return P256.verifySignatureAllowMalleability(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
    }
}

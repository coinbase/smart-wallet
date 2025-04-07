// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Ownable} from "solady/auth/Ownable.sol";
import {Base64} from "solady/utils/Base64.sol";
import {JSONParserLib} from "solady/utils/JSONParserLib.sol";

import {MultiOwnable} from "../MultiOwnable.sol";

import {IDPOracle} from "./IDPOracle.sol";
import {Verifier} from "./Verifier.sol";

contract ZKLogin is Ownable {
    using JSONParserLib for JSONParserLib.Item;

    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    bytes32 public constant KID = keccak256('"kid"');
    bytes32 public constant ALG = keccak256('"alg"');
    bytes32 public constant TYP = keccak256('"typ"');
    bytes32 public constant RS256 = keccak256('"RS256"');
    bytes32 public constant JWT = keccak256('"JWT"');

    bytes constant SHA256_DER_PREFIX = hex"3031300d060960864801650304020105000420";
    uint256 constant MAX_JWT_HEADER_JSON_LEN = 120;
    uint256 constant MAX_JWT_HEADER_BASE64_LEN = MAX_JWT_HEADER_JSON_LEN * 8 / 6;
    uint256 constant MAX_NONCE_LEN = 86;

    address public immutable idpOracle;
    address public immutable verifier;

    // TODO: One account should be able to register multiple zkAddrs.
    mapping(address account => bytes32 zkAddr) public zkAddrs;

    constructor(address idpOracle_, address verifier_) {
        idpOracle = idpOracle_;
        verifier = verifier_;
    }

    /// @notice Registers a zkAddr for msg.sender.
    /// @param zkAddr The zkAddr to register.
    function setZkAddr(bytes32 zkAddr) external {
        zkAddrs[msg.sender] = zkAddr;
    }

    function recoverAccount(
        address account,
        address idp,
        bytes32 jwtHash,
        string calldata jwtHeaderJson,
        bytes calldata jwtSignature,
        bytes calldata newOwner,
        Proof calldata proof
    ) external {
        // Verify the JWT header and get the kid.
        string memory kid = _processJwtHeader(jwtHeaderJson);

        // Verify the JWT signature.
        _verifyJwtSignature({idp: idp, jwtHash: jwtHash, signature: jwtSignature, kid: kid});

        // Verify the ZkProof.
        string memory jwtHeaderBase64 = Base64.encode({data: bytes(jwtHeaderJson), fileSafe: true, noPadding: true});
        uint256[249] memory input = _buildPublicInputs({
            account: account,
            newOwner: newOwner,
            jwtHash: jwtHash,
            jwtHeaderBase64: bytes(jwtHeaderBase64)
        });

        Verifier(verifier).verifyProof({
            proof: proof.proof,
            commitments: proof.commitments,
            commitmentPok: proof.commitmentPok,
            input: input
        });

        // Recover the account.
        if (newOwner.length == 32) {
            address owner = abi.decode(newOwner, (address));
            MultiOwnable(account).addOwnerAddress(owner);
        } else {
            (bytes32 x, bytes32 y) = abi.decode(newOwner, (bytes32, bytes32));
            MultiOwnable(account).addOwnerPublicKey(x, y);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Processes the JWT header and returns the kid.
    /// @dev This function parses the JWT header JSON and extracts the kid while also validating
    ///      that the header contains the correct algorithm (RS256) and type (JWT).
    /// @param jwtHeaderJson The JSON header of the JWT.
    /// @return kid The kid from the JWT header.
    function _processJwtHeader(string calldata jwtHeaderJson) private pure returns (string memory kid) {
        string memory alg;
        string memory typ;

        JSONParserLib.Item[] memory children = JSONParserLib.parse(jwtHeaderJson).children();
        if (children.length != 3) {
            revert("Invalid JWT header");
        }

        for (uint256 i = 0; i < children.length; i++) {
            JSONParserLib.Item memory child = children[i];
            string memory key = child.key();

            if (keccak256(bytes(key)) == ALG) {
                alg = child.value();
            } else if (keccak256(bytes(key)) == TYP) {
                typ = child.value();
            } else if (keccak256(bytes(key)) == KID) {
                kid = JSONParserLib.decodeString(child.value());
            }
        }

        if (keccak256(bytes(alg)) != RS256) {
            revert("Invalid algorithm");
        }

        if (keccak256(bytes(typ)) != JWT) {
            revert("Invalid type");
        }
    }

    /// @notice Verifies an RSA256 (PKCS#1 v1.5 and SHA-256) signature over a JWT hash.
    /// @dev This function uses the modular exponentiation precompile (address 0x05) to perform RSA verification.
    ///      It assumes the DigestInfo is SHA-256 encoded as per PKCS#1 v1.5.
    /// @param idp The identity provider's address used to look up the public key.
    /// @param jwtHash The 32-byte SHA-256 hash of the JWT signing input (header.payload).
    /// @param signature The RSA signature to verify (must match the modulus length).
    /// @param kid The key ID used to retrieve the correct RSA public key from the identity provider.
    function _verifyJwtSignature(address idp, bytes32 jwtHash, bytes calldata signature, string memory kid)
        private
        view
    {
        IDPOracle.Pk memory pk = IDPOracle(idpOracle).getPk(idp, kid);

        // Sanity checks on signature and modulus length.
        require(signature.length == pk.n.length, "Invalid signature length");

        // DigestInfo(SHA256(msg)) = 19-byte DER prefix + 32-byte hash = 51 bytes
        // Padding must be ≥ 8 bytes, so minimum total encoded length = 11 + 51
        require(pk.n.length >= 11 + SHA256_DER_PREFIX.length + 32, "Modulus too small for SHA-256 DigestInfo");

        // Compute: decoded = signature^e mod n
        bytes memory em = _rsaModExp({base: signature, exponent: pk.e, modulus: pk.n});
        require(em.length == pk.n.length, "Unexpected modexp output length");

        // Validate decoded PKCS#1 v1.5 structure.
        _checkPkcs1v15Sha256Encoding({em: em, expectedHash: jwtHash});
    }

    /// @dev Performs modular exponentiation using the EVM's precompile at address 0x05.
    /// @param base The base (e.g., the signature) as a byte array.
    /// @param exponent The public exponent `e`.
    /// @param modulus The RSA modulus `n`.
    /// @return result The output of base^exponent mod modulus.
    function _rsaModExp(bytes memory base, bytes memory exponent, bytes memory modulus)
        private
        view
        returns (bytes memory result)
    {
        bytes memory input = abi.encode(base.length, exponent.length, modulus.length);
        input = abi.encodePacked(input, base, exponent, modulus);

        (bool ok, bytes memory output) = address(5).staticcall(input);
        require(ok, "ModExp precompile failed");
        return output;
    }

    /// @dev Checks that the PKCS#1 v1.5 decoded message matches SHA-256 DigestInfo structure.
    ///      Expected format: 0x00 || 0x01 || PS (0xff...) || 0x00 || DigestInfo
    /// @param em The result of RSA decoding (i.e., signature^e mod n).
    /// @param expectedHash The SHA-256 hash the DigestInfo should contain.
    function _checkPkcs1v15Sha256Encoding(bytes memory em, bytes32 expectedHash) private pure {
        require(em[0] == 0x00 && em[1] == 0x01, "Invalid PKCS#1 v1.5 header");

        uint256 i = 2;

        // Skip over 0xff padding bytes.
        while (i < em.length && em[i] == 0xff) {
            unchecked {
                i++;
            }
        }

        // Expect a 0x00 delimiter after padding.
        require(i < em.length && em[i] == 0x00, "Missing 0x00 after padding");
        unchecked {
            i++;
        }

        uint256 digestInfoLen = SHA256_DER_PREFIX.length + 32;
        require(em.length - i == digestInfoLen, "Invalid DigestInfo length");

        // Validate the DER-encoded SHA-256 prefix.
        for (uint256 j = 0; j < SHA256_DER_PREFIX.length; j++) {
            require(em[i + j] == SHA256_DER_PREFIX[j], "Invalid DigestInfo prefix");
        }

        // Validate the SHA-256 hash matches the expected hash.
        for (uint256 j = 0; j < 32; j++) {
            require(em[i + SHA256_DER_PREFIX.length + j] == expectedHash[j], "SHA-256 hash mismatch");
        }
    }

    /// @dev Builds the public inputs for the ZK proof.
    /// @param account The account from which to retrieve the zkAddr.
    /// @param newOwner The new owner of the account to register.
    /// @param jwtHash The SHA-256 hash of the JWT signing input (header.payload).
    /// @param jwtHeaderBase64 The base64-encoded JWT header.
    /// @return input The public inputs for the ZK proof.
    function _buildPublicInputs(address account, bytes calldata newOwner, bytes32 jwtHash, bytes memory jwtHeaderBase64)
        private
        view
        returns (uint256[249] memory input)
    {
        bytes32 zkAddr = zkAddrs[account];

        for (uint256 i; i < jwtHeaderBase64.length; i++) {
            input[i] = uint256(uint8(jwtHeaderBase64[i]));
        }

        uint256 offset = MAX_JWT_HEADER_BASE64_LEN;
        input[offset++] = jwtHeaderBase64.length;

        string memory nonce = string.concat('"', Base64.encode({data: newOwner, fileSafe: true, noPadding: true}), '"');
        for (uint256 i; i < bytes(nonce).length; i++) {
            input[offset + i] = uint256(uint8(bytes(nonce)[i]));
        }

        offset += MAX_NONCE_LEN;
        input[offset++] = uint256(jwtHash >> 8);
        input[offset++] = uint256(zkAddr >> 8);
    }
}

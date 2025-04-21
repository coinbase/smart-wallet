// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Ownable} from "solady/auth/Ownable.sol";

import {MultiOwnable} from "../MultiOwnable.sol";

import {IDPOracle} from "./IDPOracle.sol";
import {Verifier} from "./Verifier.sol";

import {console2} from "forge-std/console2.sol";

contract ZKLogin is Ownable {
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    uint256 constant NB_PUBLIC_INPUTS = 36;

    uint256 constant ELEMENT_SIZE = 31;
    uint256 constant MAX_EPH_PUB_KEY_CHUNKS = 64;
    uint256 constant MAX_EPH_PUB_KEY_BYTES = (MAX_EPH_PUB_KEY_CHUNKS + ELEMENT_SIZE - 1) / ELEMENT_SIZE;

    uint256 constant MOD_1e2048_NB_LIMBS = 32;
    uint256 constant MOD_1e2048_BITS_PER_LIMB = 64;

    address public immutable idpOracle;
    address public immutable verifier;

    mapping(address account => mapping(bytes32 zkAddr => bool registered)) public zkAddrs;

    constructor(address idpOracle_, address verifier_) {
        idpOracle = idpOracle_;
        verifier = verifier_;
    }

    /// @notice Registers a zkAddr for msg.sender.
    /// @param zkAddr The zkAddr to register.
    function setZkAddr(bytes32 zkAddr) external {
        zkAddrs[msg.sender][zkAddr] = true;
    }

    function recoverAccount(
        address account,
        bytes32 zkAddr,
        address idp,
        string calldata kid,
        bytes calldata ephPubKey,
        Proof calldata proof
    ) external {
        require(zkAddrs[account][zkAddr], "ZKLogin: ZK address not registered");

        IDPOracle.Pk memory idpPubKey = IDPOracle(idpOracle).getPk({idp: idp, kid: kid});
        require(idpPubKey.n.length > 0 && idpPubKey.e.length > 0, "ZKLogin: IDP not registered");

        uint256[NB_PUBLIC_INPUTS] memory input =
            _buildInputs({idpPubKeyN: idpPubKey.n, ephPubKey: ephPubKey, zkAddr: zkAddr});

        Verifier(verifier).verifyProof({
            proof: proof.proof,
            commitments: proof.commitments,
            commitmentPok: proof.commitmentPok,
            input: input
        });

        // Recover the account.
        if (ephPubKey.length == 20) {
            address owner = address(bytes20(ephPubKey));
            MultiOwnable(account).addOwnerAddress(owner);
        } else {
            (bytes32 x, bytes32 y) = abi.decode(ephPubKey, (bytes32, bytes32));
            MultiOwnable(account).addOwnerPublicKey(x, y);
        }
    }

    function _buildInputs(bytes memory idpPubKeyN, bytes calldata ephPubKey, bytes32 zkAddr)
        internal
        pure
        returns (uint256[NB_PUBLIC_INPUTS] memory input)
    {
        uint256[] memory idpPubKeyNLimbs = _bytesToLimbs(idpPubKeyN);
        for (uint256 i; i < idpPubKeyNLimbs.length; i++) {
            input[i] = idpPubKeyNLimbs[i];
        }
        uint256 offset = idpPubKeyNLimbs.length;

        uint256[MAX_EPH_PUB_KEY_BYTES] memory ephPubKeyElements = _ephPubKeyToElements(ephPubKey);
        for (uint256 i; i < ephPubKeyElements.length; i++) {
            input[offset + i] = ephPubKeyElements[i];
        }
        offset += ephPubKeyElements.length;

        input[offset] = uint256(zkAddr);
    }

    function _ephPubKeyToElements(bytes calldata ephPubKey)
        private
        pure
        returns (uint256[MAX_EPH_PUB_KEY_BYTES] memory elements)
    {
        uint256[] memory elements_ = _bytesToElements(ephPubKey);
        for (uint256 i; i < elements_.length; i++) {
            elements[i] = elements_[i];
        }
    }

    function _bytesToElements(bytes calldata b) private pure returns (uint256[] memory elements) {
        uint256 l = b.length;
        uint256 count = l / ELEMENT_SIZE;
        uint256 ceilCount = (l + ELEMENT_SIZE - 1) / ELEMENT_SIZE;
        uint256 bitShift = 256 - ELEMENT_SIZE * 8;

        elements = new uint256[](ceilCount);
        for (uint256 i; i < count; i++) {
            bytes memory chunkBytes = b[i * ELEMENT_SIZE:(i + 1) * ELEMENT_SIZE];
            bytes32 chunk = bytes32(chunkBytes) >> bitShift;
            elements[i] = uint256(chunk);
        }

        uint256 remainingBytes = l % ELEMENT_SIZE;
        if (remainingBytes > 0) {
            bytes memory chunkBytes = b[count * ELEMENT_SIZE:];
            bytes32 chunk = bytes32(chunkBytes) >> bitShift;
            uint256 remainingBitShift = (ELEMENT_SIZE - remainingBytes) * 8;
            chunk >>= remainingBitShift;

            elements[count] = uint256(chunk);
        }
    }

    function _bytesToLimbs(bytes memory b) private pure returns (uint256[] memory limbs) {
        uint256 l = MOD_1e2048_NB_LIMBS;
        uint256 bytesPerLimb = MOD_1e2048_BITS_PER_LIMB / 8;

        limbs = new uint256[](l);
        for (uint256 i; i < l; i++) {
            for (uint256 j; j < bytesPerLimb; j++) {
                bytes1 b1 = b[i * bytesPerLimb + j];

                uint256 u8 = uint8(b1);
                uint256 bitShift = (bytesPerLimb - j - 1) * 8;
                limbs[l - i - 1] |= u8 << bitShift;
            }
        }
    }
}

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

    function recoverAccount(address account, bytes calldata ephPk, Proof calldata proof) external {
        uint256[37] memory input;

        Verifier(verifier).verifyProof({
            proof: proof.proof,
            commitments: proof.commitments,
            commitmentPok: proof.commitmentPok,
            input: input
        });

        // Recover the account.
        if (ephPk.length == 32) {
            address owner = abi.decode(ephPk, (address));
            MultiOwnable(account).addOwnerAddress(owner);
        } else {
            (bytes32 x, bytes32 y) = abi.decode(ephPk, (bytes32, bytes32));
            MultiOwnable(account).addOwnerPublicKey(x, y);
        }
    }
}

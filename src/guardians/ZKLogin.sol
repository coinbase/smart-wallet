// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Ownable} from "solady/auth/Ownable.sol";

import {MultiOwnable} from "../MultiOwnable.sol";
import {Verifier} from "./Verifier.sol";

contract ZKLogin is Ownable {
    mapping(address account => bytes32 signer) public zkSigners;

    function setZkSigner(bytes32 signer) external {
        zkSigners[msg.sender] = signer;
    }

    function recoverAccount(address account, bytes calldata newOwner, bytes calldata proof) external {
        bytes32 signer = zkSigners[account];

        // TODO: Verify proof.

        // Recover the account.
        if (newOwner.length == 160) {
            address owner = abi.decode(newOwner, (address));
            MultiOwnable(account).addOwnerAddress(owner);
        } else {
            (bytes32 x, bytes32 y) = abi.decode(newOwner, (bytes32, bytes32));
            MultiOwnable(account).addOwnerPublicKey(x, y);
        }
    }
}

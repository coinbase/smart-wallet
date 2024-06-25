// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {OnitSmartWallet, UserOperation} from "../../src/OnitSmartWallet.sol";

contract MockEntryPoint {
    mapping(address => uint256) public balanceOf;

    function depositTo(address to) public payable {
        balanceOf[to] += msg.value;
    }

    function withdrawTo(address to, uint256 amount) public payable {
        balanceOf[msg.sender] -= amount;
        (bool success,) = payable(to).call{value: amount}("");
        require(success);
    }

    function validateUserOp(
        address account,
        UserOperation memory userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) public payable returns (uint256 validationData) {
        validationData = OnitSmartWallet(payable(account)).validateUserOp(userOp, userOpHash, missingAccountFunds);
    }

    receive() external payable {
        depositTo(msg.sender);
    }
}

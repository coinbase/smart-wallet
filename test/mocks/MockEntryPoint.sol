// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {ERC4337Account, UserOperation} from "../../src/ERC4337Account.sol";

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
        validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, missingAccountFunds);
    }

    receive() external payable {
        depositTo(msg.sender);
    }
}

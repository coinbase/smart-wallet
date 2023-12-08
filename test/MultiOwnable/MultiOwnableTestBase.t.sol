// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test, console2, stdError} from "forge-std/Test.sol";

import "../mocks/MockMultiOwnable.sol";

contract MultiOwnableTestBase is Test {
    MockMultiOwnable mock = new MockMultiOwnable();
    address owner1Address = address(0xb0b);
    bytes owner1Bytes = abi.encode(owner1Address);
    // public key x,y
    bytes owner2Bytes = abi.encode(
        0x65a2fa44daad46eab0278703edb6c4dcf5e30b8a9aec09fdc71a56f52aa392e4,
        0x4a7a9e4604aa36898209997288e902ac544a555e4b5e0a9efef2b59233f3f437
    );
    bytes[] owners;

    function setUp() public virtual {
        owners.push(owner1Bytes);
        owners.push(owner2Bytes);
        mock.init(owners);
    }
}

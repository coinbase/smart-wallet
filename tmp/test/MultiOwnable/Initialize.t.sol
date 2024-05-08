// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import "../mocks/MockMultiOwnable.sol";

contract MultiOwnableInitializeTest is Test {
    MockMultiOwnable mock = new MockMultiOwnable();
    bytes[] owners;

    function testRevertsIfLength32ButLargerThanAddress() public {
        bytes memory badOwner = abi.encode(uint256(type(uint160).max) + 1);
        owners.push(badOwner);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.InvalidEthereumAddressOwner.selector, badOwner));
        mock.init(owners);
    }

    function testRevertsIfLengthNot32Or64() public {
        bytes memory badOwner = abi.encodePacked(type(uint256).max, uint8(1));
        owners.push(badOwner);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.InvalidOwnerBytesLength.selector, badOwner));
        mock.init(owners);
    }

    function testRevertsIfLength32NotAddress() public {
        bytes memory badOwner = abi.encodePacked(type(uint256).max);
        owners.push(badOwner);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.InvalidEthereumAddressOwner.selector, badOwner));
        mock.init(owners);
    }
}

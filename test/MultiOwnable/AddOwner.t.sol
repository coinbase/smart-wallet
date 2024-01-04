// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./AddOwnerBase.t.sol";

contract AddOwnerTest is AddOwnerBaseTest {
    function testRevertsIfAlreadyOwner() public {
        vm.startPrank(owner1Address);
        _addOwner();
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.AlreadyOwner.selector, newOwner));
        _addOwner();
    }

    function testIncreasesOwnerIndex() public {
        uint8 before = mock.nextOwnerIndex();
        vm.prank(owner1Address);
        mock.addOwner(newOwner);
        assertEq(before + 1, mock.nextOwnerIndex());
    }

    function testRevertsAfter255() public {
        vm.startPrank(owner1Address);
        // two owners added in setup
        for (uint256 i = 0; i < 253; i++) {
            mock.addOwner(abi.encode(i));
        }
        assertEq(mock.nextOwnerIndex(), 255);
        vm.expectRevert(stdError.arithmeticError);
        mock.addOwner(abi.encode("dead"));
    }

    function _addOwner() internal override {
        mock.addOwner(newOwner);
    }

    function _index() internal view override returns (uint8) {
        return mock.nextOwnerIndex();
    }
}

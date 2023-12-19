// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./MultiOwnableTestBase.t.sol";

abstract contract AddOwnerBaseTest is MultiOwnableTestBase {
    address newOwner = address(0x404);

    function testSetsIsOwner() public {
        vm.prank(owner1Address);
        _addOwner();
        assert(mock.isOwner(newOwner));
    }

    function testSetsOwnerAtIndex() public {
        uint8 index = _index();
        vm.prank(owner1Address);
        _addOwner();
        assertEq(mock.ownerAtIndex(index), abi.encode(newOwner));
    }

    function testEmitsAddOwner() public {
        vm.expectEmit(true, true, true, false);
        emit MultiOwnable.AddOwner(abi.encode(newOwner), owner1Bytes, _index());
        vm.prank(owner1Address);
        _addOwner();
    }

    function testRevertsIfCalledByNonOwner() public {
        vm.startPrank(address(0xdead));
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        _addOwner();
    }

    function _addOwner() internal virtual;
    function _index() internal virtual returns (uint8);
}

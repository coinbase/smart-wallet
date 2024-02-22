// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./MultiOwnableTestBase.t.sol";

abstract contract AddOwnerBaseTest is MultiOwnableTestBase {
    function testSetsIsOwner() public {
        vm.prank(owner1Address);
        _addOwner();
        assert(mock.isOwnerAddress(abi.decode(_newOwner(), (address))));
    }

    function testSetsOwnerAtIndex() public {
        uint8 index = _index();
        vm.prank(owner1Address);
        _addOwner();
        assertEq(mock.ownerAtIndex(index), _newOwner());
    }

    function testEmitsAddOwner() public {
        vm.expectEmit(true, true, true, true);
        emit MultiOwnable.AddOwner(_index(), _newOwner());
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
    function _newOwner() internal virtual returns (bytes memory);
}

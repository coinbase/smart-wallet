// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./MultiOwnableTestBase.t.sol";

contract RemoveOwnerAtIndexTest is MultiOwnableTestBase {
    function testRemovesOwner() public {
        vm.prank(owner1Address);
        mock.removeOwnerAtIndex(_index(), owner2Bytes);
        assertFalse(mock.isOwnerBytes(owner2Bytes));
    }

    function testRemovesOwnerAtIndex() public {
        uint8 index = _index();
        vm.prank(owner1Address);
        mock.removeOwnerAtIndex(index, owner2Bytes);
        assertEq(mock.ownerAtIndex(index), hex"");
    }

    function testEmitsRemoveOwner() public {
        vm.expectEmit(true, true, true, true);
        emit MultiOwnable.RemoveOwner(_index(), owner2Bytes);
        vm.prank(owner1Address);
        mock.removeOwnerAtIndex(_index(), owner2Bytes);
    }

    function testRevertsIfCalledByNonOwner(address a) public {
        vm.assume(a != owner1Address && a != address(mock));
        vm.startPrank(a);
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        mock.removeOwnerAtIndex(_index(), abi.encode(a));
    }

    function testRevertsIfNoOwnerAtIndex() public {
        uint8 index = 10;
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.NoOwnerAtIndex.selector, index));
        vm.prank(owner1Address);
        mock.removeOwnerAtIndex(index, owner1Bytes);
    }

    function testRevertsIfWrongOwnerAtIndex() public {
        uint8 index = _index();
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.WrongOwnerAtIndex.selector, index, owner1Bytes));
        vm.prank(owner1Address);
        mock.removeOwnerAtIndex(index, owner1Bytes);
    }

    function _index() internal virtual returns (uint8) {
        return 1;
    }
}

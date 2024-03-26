// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./MultiOwnableTestBase.t.sol";

contract RemoveOwnerAtIndexTest is MultiOwnableTestBase {
    function testRemovesOwner() public {
        vm.prank(owner1Address);
        _removeOwner(owner2Bytes);
        assertFalse(mock.isOwnerBytes(owner2Bytes));
    }

    function testRemovesOwnerAtIndex() public {
        uint8 index = _index();
        vm.prank(owner1Address);
        _removeOwner(owner2Bytes);
        assertEq(mock.ownerAtIndex(index), hex"");
    }

    function testEmitsRemoveOwner() public {
        vm.expectEmit(true, true, true, true);
        emit MultiOwnable.RemoveOwner(_index(), owner2Bytes);
        vm.prank(owner1Address);
        _removeOwner(owner2Bytes);
    }

    function testRevertsIfCalledByNonOwner() public {
        vm.startPrank(address(0xdead));
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        _removeOwner(abi.encode(0xdead));
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

    function _removeOwner(bytes memory owner) internal virtual {
        mock.removeOwnerAtIndex(_index(), owner);
    }

    function _index() internal virtual returns (uint8) {
        return 1;
    }
}

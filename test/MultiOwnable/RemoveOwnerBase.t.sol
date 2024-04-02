// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./MultiOwnableTestBase.t.sol";

abstract contract RemoveOwnerBaseTest is MultiOwnableTestBase {
    uint256 index = 1;
    bytes ownerToRemove = owner2Bytes;

    function test_removesOwner() public {
        _removeOwner();
        assertFalse(mock.isOwnerBytes(ownerToRemove));
    }

    function test_removesOwnerAtIndex() public {
        _removeOwner();
        assertEq(mock.ownerAtIndex(index), hex"");
    }

    function test_emitsRemoveOwner() public {
        vm.expectEmit(true, true, true, true);
        emit MultiOwnable.RemoveOwner(index, ownerToRemove);
        _removeOwner();
    }

    function test_revert_whenCalledByNonOwner(address a) public {
        vm.assume(a != owner1Address && a != address(mock));
        vm.startPrank(a);
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        mock.removeOwnerAtIndex(10, owner1Bytes);
    }

    function test_revert_whenNoOwnerAtIndex() public {
        index = 10;
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.NoOwnerAtIndex.selector, index));
        _removeOwner();
    }

    function test_revert_whenWrongOwnerAtIndex() public {
        bytes memory wrongOwner = "bad";
        vm.expectRevert(
            abi.encodeWithSelector(MultiOwnable.WrongOwnerAtIndex.selector, index, wrongOwner, ownerToRemove)
        );
        ownerToRemove = wrongOwner;
        _removeOwner();
    }

    function _removeOwner() internal virtual {
        vm.prank(owner1Address);
        mock.removeOwnerAtIndex(index, ownerToRemove);
    }
}

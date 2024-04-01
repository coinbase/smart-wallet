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

    function test_reverts_ifIsLastOwner() public {
        uint256 owners = 100;
        MockMultiOwnable mock = new MockMultiOwnable();
        address firstOnwer = makeAddr("first");
        bytes[] memory initialOwners = new bytes[](1);
        initialOwners[0] = abi.encode(firstOnwer);
        mock.init(initialOwners);
        assertEq(mock.nextOwnerIndex(), 1);
        assertEq(mock.ownersRemoved(), 0);
        vm.startPrank(firstOnwer);
        for (uint256 i; i < owners; i++) {
            mock.addOwnerAddress(makeAddr(string(abi.encodePacked(i))));
            assertEq(mock.nextOwnerIndex(), i + 2);
        }
        for (uint256 i = 1; i < owners + 1; i++) {
            mock.removeOwnerAtIndex(i, abi.encode(makeAddr(string(abi.encodePacked(i - 1)))));
            assertEq(mock.ownersRemoved(), i);
        }
        vm.expectRevert(MultiOwnable.LastOwner.selector);
        mock.removeOwnerAtIndex(0, abi.encode(firstOnwer));
    }

    function _index() internal virtual returns (uint8) {
        return 1;
    }
}

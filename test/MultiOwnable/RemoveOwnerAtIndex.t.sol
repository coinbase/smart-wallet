// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./RemoveOwnerBase.t.sol";

contract RemoveOwnerAtIndexTest is RemoveOwnerBaseTest {
    function test_reverts_ifIsLastOwner() public {
        // note this could be fuzzed but it takes a very long time to complete
        uint256 owners = 100;
        MockMultiOwnable mock = new MockMultiOwnable();
        address firstOnwer = makeAddr("first");
        bytes[] memory initialOwners = new bytes[](1);
        initialOwners[0] = abi.encode(firstOnwer);
        mock.init(initialOwners);
        assertEq(mock.nextOwnerIndex(), 1);
        assertEq(mock.removedOwnersCount(), 0);
        assertEq(mock.ownerCount(), 1);
        vm.startPrank(firstOnwer);
        for (uint256 i; i < owners; i++) {
            mock.addOwnerAddress(makeAddr(string(abi.encodePacked(i))));
            assertEq(mock.nextOwnerIndex(), i + 2);
            assertEq(mock.ownerCount(), i + 2);
        }
        for (uint256 i = 1; i < owners + 1; i++) {
            mock.removeOwnerAtIndex(i, abi.encode(makeAddr(string(abi.encodePacked(i - 1)))));
            assertEq(mock.removedOwnersCount(), i);
            assertEq(mock.ownerCount(), owners - i + 1);
        }
        vm.expectRevert(MultiOwnable.LastOwner.selector);
        mock.removeOwnerAtIndex(0, abi.encode(firstOnwer));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./RemoveOwnerBase.t.sol";

contract RemoveLastOwnerTest is RemoveOwnerBaseTest {
    function setUp() public override {
        owners.push(owner1Bytes);
        mock.init(owners);
        index = 0;
        ownerToRemove = owner1Bytes;
    }

    function test_reverts_whenNotLastOwner() public {
        vm.prank(owner1Address);
        mock.addOwnerPublicKey("x", "y");
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.NotLastOwner.selector, 2));
        _removeOwner();
    }

    function test_reverts_whenNoOwnerAtIndex() public {
        index = 10;
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.NoOwnerAtIndex.selector, index));
        _removeOwner();
    }

    function _removeOwner() internal override returns (bool) {
        vm.prank(owner1Address);
        mock.removeLastOwner(index, ownerToRemove);
    }
}

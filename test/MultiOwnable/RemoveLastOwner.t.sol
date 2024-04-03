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

    function _removeOwner() internal override {
        vm.prank(owner1Address);
        mock.removeLastOwner(index, ownerToRemove);
    }
}

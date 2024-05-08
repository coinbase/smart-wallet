// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./AddOwnerBase.t.sol";

contract AddOwnerAddressTest is AddOwnerBaseTest {
    function testSetsIsOwner() public override {
        vm.prank(owner1Address);
        _addOwner();
        assertTrue(mock.isOwnerAddress(abi.decode(_newOwner(), (address))));
    }

    function testRevertsIfAlreadyOwner() public {
        vm.startPrank(owner1Address);
        _addOwner();
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.AlreadyOwner.selector, _newOwner()));
        _addOwner();
    }

    function testIncreasesOwnerIndex() public {
        uint256 before = mock.nextOwnerIndex();
        vm.prank(owner1Address);
        mock.addOwnerAddress(abi.decode(_newOwner(), (address)));
        assertEq(before + 1, mock.nextOwnerIndex());
    }

    function _addOwner() internal override {
        mock.addOwnerAddress(abi.decode(_newOwner(), (address)));
    }

    function _index() internal view override returns (uint256) {
        return mock.nextOwnerIndex();
    }

    function _newOwner() internal pure override returns (bytes memory) {
        return abi.encode(address(0x404));
    }
}

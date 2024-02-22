// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./AddOwnerBase.t.sol";

contract AddOwnerAddressTest is AddOwnerBaseTest {
    function testRevertsIfAlreadyOwner() public {
        vm.startPrank(owner1Address);
        _addOwner();
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.AlreadyOwner.selector, _newOwner()));
        _addOwner();
    }

    function testIncreasesOwnerIndex() public {
        uint8 before = mock.nextOwnerIndex();
        vm.prank(owner1Address);
        mock.addOwnerAddress(abi.decode(_newOwner(), (address)));
        assertEq(before + 1, mock.nextOwnerIndex());
    }

    function testRevertsAfter255() public {
        vm.startPrank(owner1Address);
        // two owners added in setup
        for (uint256 i = 0; i < 253; i++) {
            mock.addOwnerAddress(address(uint160(i)));
        }
        assertEq(mock.nextOwnerIndex(), 255);
        vm.expectRevert(stdError.arithmeticError);
        mock.addOwnerAddress(address(0xdead));
    }

    function _addOwner() internal override {
        mock.addOwnerAddress(abi.decode(_newOwner(), (address)));
    }

    function _index() internal view override returns (uint8) {
        return mock.nextOwnerIndex();
    }

    function _newOwner() internal pure override returns (bytes memory) {
        return abi.encode(address(0x404));
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./AddOwnerBase.t.sol";

contract AddOwnerPublicKeyAtIndexTest is AddOwnerBaseTest {
    function setUp() public override {
        super.setUp();
        vm.startPrank(owner1Address);
        for (uint256 i = 0; i < 253; i++) {
            mock.addOwnerAddress(address(uint160(i)));
        }
        mock.removeOwnerAtIndex(_index());
        vm.stopPrank();
    }

    function testRevertsIfAlreadyOwner() public {
        vm.startPrank(owner1Address);
        _addOwner();
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.IndexNotEmpty.selector, _index(), _newOwner()));
        _addOwner();
    }

    function testRevertsIfOwnerIndexNot255() public {
        MockMultiOwnable mock2 = new MockMultiOwnable();
        mock2.init(owners);
        mock = mock2;
        vm.expectRevert(MultiOwnable.UseAddOwner.selector);
        vm.startPrank(owner1Address);
        _addOwner();
    }

    function _addOwner() internal override {
        (bytes32 x, bytes32 y) = abi.decode(_newOwner(), (bytes32, bytes32));
        mock.addOwnerPublicKeyAtIndex(x, y, _index());
    }

    function _index() internal pure override returns (uint8) {
        return 2;
    }

    function _newOwner() internal pure override returns (bytes memory) {
        return abi.encode(uint256(1), uint256(1));
    }
}

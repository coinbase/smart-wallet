// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./AddOwnerBase.t.sol";

contract AddOwnerPublicKeyTest is AddOwnerBaseTest {
    function testSetsIsOwner() public override {
        vm.prank(owner1Address);
        _addOwner();
        assertTrue(mock.isOwnerBytes(_newOwner()));
    }

    function testFuzzIsOwnerPublicKey(bytes32 x, bytes32 y) external {
        vm.assume(x > 0 && y > 0);
        vm.startPrank(owner1Address);
        mock.addOwnerPublicKey(x, y);
        bytes memory xy = abi.encode(x, y);
        assert(mock.isOwnerBytes(xy));
        assert(mock.isOwnerPublicKey(x, y));
    }

    function _addOwner() internal override returns (bool) {
        (bytes32 x, bytes32 y) = abi.decode(_newOwner(), (bytes32, bytes32));
        return mock.addOwnerPublicKey(x, y);
    }

    function _index() internal view override returns (uint256) {
        return mock.nextOwnerIndex();
    }

    function _newOwner() internal pure override returns (bytes memory) {
        return abi.encode(uint256(1), uint256(1));
    }
}

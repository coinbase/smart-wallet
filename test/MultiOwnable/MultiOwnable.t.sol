// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {MultiOwnable, MultiOwnableStorage} from "../../src/MultiOwnable.sol";

contract MultiOwnableTest is Test {
    MultiOwnable private sut;

    function setUp() public {
        sut = new MultiOwnable();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            MODIFIERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    modifier withSenderSelf() {
        vm.startPrank(address(sut));
        _;
        vm.stopPrank();
    }

    modifier withOwner(uint256 ksKey, uint256 ksKeyType) {
        _cheat_AddOwner({ksKey: ksKey, ksKeyType: _uintToKsKeyType(ksKeyType, false)});
        _;
    }

    modifier withOwners(uint256 ownerCount) {
        uint256 startKey = uint256(keccak256("start-key")) - 1;
        uint256 startKeyType = uint256(keccak256("start-key-type")) - 1;

        for (uint256 i = 0; i < ownerCount; i++) {
            _cheat_AddOwner({ksKey: startKey + i, ksKeyType: _uintToKsKeyType(startKeyType + i, false)});
        }
        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             TESTS                                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @custom:test-section addOwner

    function test_addOwner_reverts_whenSenderIsNotSelf(address sender, uint256 ksKey, uint256 ksKeyType) external {
        vm.assume(sender != address(sut));
        vm.prank(sender);

        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        sut.addOwner(ksKey, _uintToKsKeyType(ksKeyType, true));
    }

    function test_addOwner_reverts_whenKsKeyTypeIsNone(uint256 ksKey) external withSenderSelf {
        vm.expectRevert(MultiOwnable.KeyspaceKeyTypeCantBeNone.selector);
        sut.addOwner(ksKey, MultiOwnable.KeyspaceKeyType.None);
    }

    function test_addOwner_reverts_whenKsKeyIsAlreadyRegistered(
        uint256 ksKey,
        uint256 ksKeyType,
        uint256 ksKeyTypeRegistered
    ) external withSenderSelf withOwner(ksKey, ksKeyTypeRegistered) {
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.AlreadyOwner.selector, ksKey));
        sut.addOwner(ksKey, _uintToKsKeyType(ksKeyType, false));
    }

    function test_addOwner_registersNewKsKey(uint256 ksKey, uint256 ksKeyType) external withSenderSelf withOwners(10) {
        MultiOwnable.KeyspaceKeyType ksKeyType_ = _uintToKsKeyType(ksKeyType, false);
        sut.addOwner(ksKey, ksKeyType_);

        assertEq(uint256(sut.keyspaceKeyType(ksKey)), uint256(ksKeyType_));
    }

    function test_addOwner_incrementsOwnerCount(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwners(10)
    {
        uint256 ownerCountBefore = sut.ownerCount();

        sut.addOwner(ksKey, _uintToKsKeyType(ksKeyType, false));

        assertEq(sut.ownerCount(), ownerCountBefore + 1);
    }

    function test_addOwner_emitsOwnerAdded(uint256 ksKey, uint256 ksKeyType) external withSenderSelf withOwners(10) {
        vm.expectEmit(address(sut));
        emit MultiOwnable.OwnerAdded(ksKey);

        sut.addOwner(ksKey, _uintToKsKeyType(ksKeyType, false));
    }

    /// @custom:test-section removeOwner

    function test_removeOwner_reverts_whenSenderIsNotSelf(address sender, uint256 ksKey) external {
        vm.assume(sender != address(sut));
        vm.prank(sender);

        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        sut.removeOwner(ksKey);
    }

    function test_removeOwner_reverts_whenOnlyOneOwnerIsLeft(
        uint256 ksKey,
        uint256 ksKeyRegistered,
        uint256 ksKeyTypeRegistered
    ) external withSenderSelf withOwner(ksKeyRegistered, ksKeyTypeRegistered) {
        vm.expectRevert(MultiOwnable.LastOwner.selector);
        sut.removeOwner(ksKey);
    }

    function test_removeOwner_reverts_whenKsKeyIsNotAnOwner(uint256 ksKey) external withSenderSelf withOwners(10) {
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.NotAnOwner.selector, ksKey));
        sut.removeOwner(ksKey);
    }

    function test_removeOwner_unregistersKsKey(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwner(ksKey, ksKeyType)
        withOwners(10)
    {
        sut.removeOwner(ksKey);
        assertEq(uint256(sut.keyspaceKeyType(ksKey)), uint256(MultiOwnable.KeyspaceKeyType.None));
    }

    function test_removeOwner_decrementsOwnerCount(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwner(ksKey, ksKeyType)
        withOwners(10)
    {
        uint256 ownerCountBefore = sut.ownerCount();

        sut.removeOwner(ksKey);

        assertEq(sut.ownerCount(), ownerCountBefore - 1);
    }

    function test_removeOwner_emitsOwnerRemoved(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwner(ksKey, ksKeyType)
        withOwners(10)
    {
        vm.expectEmit(address(sut));
        emit MultiOwnable.OwnerRemoved(ksKey);

        sut.removeOwner(ksKey);
    }

    /// @custom:test-section removeLastOwner

    function test_removeLastOwner_reverts_whenSenderIsNotSelf(address sender, uint256 ksKey) external {
        vm.assume(sender != address(sut));
        vm.prank(sender);

        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        sut.removeLastOwner(ksKey);
    }

    function test_removeLastOwner_reverts_whenMoreThanOneOwnersAreLeft(uint256 ksKey)
        external
        withSenderSelf
        withOwners(10)
    {
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.NotLastOwner.selector, 10));
        sut.removeLastOwner(ksKey);
    }

    function test_removeLastOwner_reverts_whenKsKeyIsNotAnOwner(uint256 ksKey) external withSenderSelf withOwners(1) {
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.NotAnOwner.selector, ksKey));
        sut.removeLastOwner(ksKey);
    }

    function test_removeLastOwner_unregistersKsKey(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwner(ksKey, ksKeyType)
    {
        sut.removeLastOwner(ksKey);
        assertEq(uint256(sut.keyspaceKeyType(ksKey)), uint256(MultiOwnable.KeyspaceKeyType.None));
    }

    function test_removeLastOwner_decrementsOwnerCount(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwner(ksKey, ksKeyType)
    {
        sut.removeLastOwner(ksKey);
        assertEq(sut.ownerCount(), 0);
    }

    function test_removeLastOwner_emitsOwnerRemoved(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwner(ksKey, ksKeyType)
    {
        vm.expectEmit(address(sut));
        emit MultiOwnable.OwnerRemoved(ksKey);

        sut.removeLastOwner(ksKey);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TESTS HELPERS                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _uintToKsKeyType(uint256 value, bool withNone) private pure returns (MultiOwnable.KeyspaceKeyType) {
        if (withNone) {
            value = value % 3;
            return MultiOwnable.KeyspaceKeyType(value);
        }

        value = value % 2;
        return MultiOwnable.KeyspaceKeyType(value + 1);
    }

    function _cheat_AddOwner(uint256 ksKey, MultiOwnable.KeyspaceKeyType ksKeyType) private {
        bytes32 slot = _MUTLI_OWNABLE_STORAGE_LOCATION();

        // Set `ownerCount += 1`;
        uint256 ownerCount = sut.ownerCount();
        vm.store(address(sut), slot, bytes32(ownerCount + 1));

        // Set `ksKeyTypes[ksKey] = ksKeyType`;
        slot = bytes32(uint256(slot) + 1);
        slot = keccak256(abi.encode(ksKey, slot));
        vm.store(address(sut), slot, bytes32(uint256(ksKeyType)));
    }

    function _MUTLI_OWNABLE_STORAGE_LOCATION() private pure returns (bytes32) {
        return 0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;
    }
}

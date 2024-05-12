// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {MultiOwnable, MultiOwnableStorage} from "../../src/MultiOwnable.sol";

import {LibMultiOwnable} from "../utils/LibMultiOwnable.sol";

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
        LibMultiOwnable.cheat_AddOwner({target: address(sut), ksKey: ksKey, ksKeyType: ksKeyType});
        _;
    }

    modifier withOwners(uint256 ownerCount) {
        uint256 startKey = uint256(keccak256("start-key")) - 1;
        uint256 startKeyType = uint256(keccak256("start-key-type")) - 1;

        for (uint256 i; i < ownerCount; i++) {
            LibMultiOwnable.cheat_AddOwner({target: address(sut), ksKey: startKey + i, ksKeyType: startKeyType + i});
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
        sut.addOwner(ksKey, LibMultiOwnable.uintToKsKeyType({value: ksKeyType, withNone: true}));
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
        sut.addOwner(ksKey, LibMultiOwnable.uintToKsKeyType({value: ksKeyType, withNone: false}));
    }

    function test_addOwner_registersNewKsKey(uint256 ksKey, uint256 ksKeyType) external withSenderSelf withOwners(10) {
        MultiOwnable.KeyspaceKeyType ksKeyType_ = LibMultiOwnable.uintToKsKeyType({value: ksKeyType, withNone: false});
        sut.addOwner(ksKey, ksKeyType_);

        assertEq(uint256(sut.keyspaceKeyType(ksKey)), uint256(ksKeyType_));
    }

    function test_addOwner_incrementsOwnerCount(uint256 ksKey, uint256 ksKeyType)
        external
        withSenderSelf
        withOwners(10)
    {
        uint256 ownerCountBefore = sut.ownerCount();

        sut.addOwner(ksKey, LibMultiOwnable.uintToKsKeyType({value: ksKeyType, withNone: false}));

        assertEq(sut.ownerCount(), ownerCountBefore + 1);
    }

    function test_addOwner_emitsOwnerAdded(uint256 ksKey, uint256 ksKeyType) external withSenderSelf withOwners(10) {
        vm.expectEmit(address(sut));
        emit MultiOwnable.OwnerAdded(ksKey);

        sut.addOwner(ksKey, LibMultiOwnable.uintToKsKeyType({value: ksKeyType, withNone: false}));
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
}

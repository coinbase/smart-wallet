// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Vm} from "forge-std/Vm.sol";

import {MultiOwnable, MultiOwnableStorage} from "../../src/MultiOwnable.sol";

library LibMultiOwnable {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         MOCK HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function cheat_AddOwner(address target, uint256 ksKey, uint256 ksKeyType) internal {
        bytes32 slot = MUTLI_OWNABLE_STORAGE_LOCATION();

        // Set `ownerCount += 1`;
        uint256 ownerCount = uint256(vm.load({target: target, slot: slot}));
        vm.store(target, slot, bytes32(ownerCount + 1));

        // Set `ksKeyTypes[ksKey] = ksKeyType`;
        slot = bytes32(uint256(slot) + 1);
        slot = keccak256(abi.encode(ksKey, slot));
        vm.store(target, slot, bytes32(uint256(uintToKsKeyType({value: ksKeyType, withNone: false}))));
    }

    function cheat_AddOwner(address target, uint256 ksKey, MultiOwnable.KeyspaceKeyType ksKeyType) internal {
        bytes32 slot = MUTLI_OWNABLE_STORAGE_LOCATION();

        // Set `ownerCount += 1`;
        uint256 ownerCount = uint256(vm.load({target: target, slot: slot}));
        vm.store(target, slot, bytes32(ownerCount + 1));

        // Set `ksKeyTypes[ksKey] = ksKeyType`;
        slot = bytes32(uint256(slot) + 1);
        slot = keccak256(abi.encode(ksKey, slot));
        vm.store(target, slot, bytes32(uint256(ksKeyType)));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TEST HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function generateKeyAndTypes(uint256 count)
        internal
        pure
        returns (MultiOwnable.KeyAndType[] memory ksKeyAndTypes)
    {
        uint256 startKey = uint256(keccak256("start-key")) - 1;
        uint256 startKeyType = uint256(keccak256("start-key-type")) - 1;

        ksKeyAndTypes = new MultiOwnable.KeyAndType[](count);

        for (uint256 i; i < count; i++) {
            uint256 ksKey = startKey + i;
            uint256 ksKeyType = startKeyType + i;

            ksKeyAndTypes[i] =
                MultiOwnable.KeyAndType({ksKey: ksKey, ksKeyType: uintToKsKeyType({value: ksKeyType, withNone: false})});
        }
    }

    function uintToKsKeyType(uint256 value, bool withNone) internal pure returns (MultiOwnable.KeyspaceKeyType) {
        if (withNone) {
            value = value % 3;
            return MultiOwnable.KeyspaceKeyType(value);
        }

        value = value % 2;
        return MultiOwnable.KeyspaceKeyType(value + 1);
    }

    function MUTLI_OWNABLE_STORAGE_LOCATION() internal pure returns (bytes32) {
        return 0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {LibClone} from "solady/utils/LibClone.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";

import {LibCoinbaseSmartWallet} from "../utils/LibCoinbaseSmartWallet.sol";

contract CoinbaseSmartWalletFactoryTest is Test {
    CoinbaseSmartWallet private sw;
    CoinbaseSmartWalletFactory private sut;

    function setUp() public {
        sw = new CoinbaseSmartWallet({keyStore_: address(0), stateVerifier_: address(0)});
        sut = new CoinbaseSmartWalletFactory(address(sw));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            MODIFIERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    modifier withAccountDeployed(uint256 kskey, uint256 ksKeyType, uint256 nonce) {
        address account =
            sut.getAddress({ksKey: kskey, ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType), nonce: nonce});
        vm.etch({target: account, newRuntimeBytecode: "Some bytecode"});

        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             TESTS                                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @custom:test-section createAccount

    function test_createAccount_deploysTheAccount_whenNotAlreadyDeployed(
        uint256 ksKey,
        uint256 ksKeyType,
        uint256 nonce
    ) external {
        address account = address(
            sut.createAccount({ksKey: ksKey, ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType), nonce: nonce})
        );
        assertTrue(account != address(0));
        assertGt(account.code.length, 0);
    }

    function test_createAccount_initializesTheAccount_whenNotAlreadyDeployed(
        uint256 ksKey,
        uint256 ksKeyType,
        uint256 nonce
    ) external {
        CoinbaseSmartWallet.KeyspaceKeyType ksKeyType_ = LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType);

        address expectedAccount = _create2Address({ksKey: ksKey, ksKeyType: ksKeyType_, nonce: nonce});
        vm.expectCall({
            callee: expectedAccount,
            data: abi.encodeCall(CoinbaseSmartWallet.initialize, (ksKey, ksKeyType_))
        });
        sut.createAccount({ksKey: ksKey, ksKeyType: ksKeyType_, nonce: nonce});
    }

    function test_createAccount_returnsTheAccountAddress_whenAlreadyDeployed(
        uint256 ksKey,
        uint256 ksKeyType,
        uint256 nonce
    ) external withAccountDeployed(ksKey, ksKeyType, nonce) {
        address account = address(
            sut.createAccount({ksKey: ksKey, ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType), nonce: nonce})
        );
        assertTrue(account != address(0));
        assertGt(account.code.length, 0);
    }

    /// @custom:test-section getAddress

    function test_getAddress_returnsTheAccountCounterfactualAddress(uint256 ksKey, uint256 ksKeyType, uint256 nonce)
        external
    {
        CoinbaseSmartWallet.KeyspaceKeyType ksKeyType_ = LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType);

        address expectedAccountAddress = _create2Address({ksKey: ksKey, ksKeyType: ksKeyType_, nonce: nonce});
        address accountAddress = sut.getAddress({ksKey: ksKey, ksKeyType: ksKeyType_, nonce: nonce});

        assertEq(accountAddress, expectedAccountAddress);
    }

    /// @custom:test-section initCodeHash

    function test_initCodeHash_returnsTheInitCodeHash() external {
        assertEq(sut.initCodeHash(), LibClone.initCodeHashERC1967(address(sw)));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TESTS HELPERS                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _create2Address(uint256 ksKey, CoinbaseSmartWallet.KeyspaceKeyType ksKeyType, uint256 nonce)
        private
        view
        returns (address)
    {
        return vm.computeCreate2Address({
            salt: _getSalt({ksKey: ksKey, ksKeyType: ksKeyType, nonce: nonce}),
            initCodeHash: LibClone.initCodeHashERC1967(address(sw)),
            deployer: address(sut)
        });
    }

    function _getSalt(uint256 ksKey, CoinbaseSmartWallet.KeyspaceKeyType ksKeyType, uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(ksKey, ksKeyType, nonce));
    }
}

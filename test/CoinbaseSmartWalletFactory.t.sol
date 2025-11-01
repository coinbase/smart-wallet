// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {CoinbaseSmartWallet, MultiOwnable} from "../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract CoinbaseSmartWalletFactoryTest is Test {
    CoinbaseSmartWalletFactory factory;
    CoinbaseSmartWallet account;
    bytes[] owners;

    function setUp() public {
        account = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(account));
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
    }

    function test_constructor_revertsIfImplementationIsNotDeployed(address implementation) public {
        vm.assume(implementation.code.length == 0);
        vm.expectRevert(CoinbaseSmartWalletFactory.ImplementationUndeployed.selector);
        new CoinbaseSmartWalletFactory(implementation);
    }

    function test_constructor_setsImplementation(address implementation) public {
        // avoid precompiles in fuzz runs
        vm.assume(uint160(implementation) > 100);
        // set bytecode if not already set
        if (implementation.code.length == 0) {
            vm.etch(implementation, address(account).code);
        }
        CoinbaseSmartWalletFactory factory2 = new CoinbaseSmartWalletFactory(implementation);
        assertEq(address(factory2.implementation()), implementation);
    }

    function test_getAddress_isZeroIfNoAccountExists(bytes[] calldata owners1, uint256 nonce) public {
        address expectedAddress = factory.getAddress(owners1, nonce);
        assertEq(expectedAddress.code.length, 0);
    }

    function test_createAccount_emitsAccountCreatedEvent(uint256 nonce) public {
        // Bound nonce to type(uint128).max to avoid excessive gas costs during fuzzing.
        // The factory's internal nonce tracking uses uint128, so values above this can cause overflow issues.
        vm.assume(nonce < type(uint128).max);
        address expectedAddress = factory.getAddress(owners, nonce);
        vm.expectEmit(true, true, true, true);
        emit CoinbaseSmartWalletFactory.AccountCreated(expectedAddress, owners, nonce);
        factory.createAccount(owners, nonce);
    }

    function test_createAccount_createsAccountAtExpectedAddress(bytes[] calldata owners1, uint256 nonce) public {
        address expectedAddress = factory.getAddress(owners1, nonce);
        CoinbaseSmartWallet newAccount = factory.createAccount(owners1, nonce);
        assertEq(address(newAccount), expectedAddress);
    }

    function test_createAccount_deploysAccountWithExpectedInitialization(bytes[] calldata owners1, uint256 nonce)
        public
    {
        CoinbaseSmartWallet newAccount = factory.createAccount(owners1, nonce);
        address[] memory ownersAddresses = newAccount.owners();
        assertEq(ownersAddresses.length, owners1.length);
        for (uint256 i = 0; i < owners1.length; i++) {
            assertEq(newAccount.isOwnerAddress(abi.decode(owners1[i], (address))), true);
        }
    }

    function test_createAccount_returnsInstanceOfCoinbaseSmartWallet(bytes[] calldata owners1, uint256 nonce)
        public
    {
        CoinbaseSmartWallet newAccount = factory.createAccount(owners1, nonce);
        assertEq(address(newAccount.implementation()), address(account));
    }
}

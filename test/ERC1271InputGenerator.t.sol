// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import {CoinbaseSmartWallet} from "../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";
import {ERC1271InputGenerator} from "../src/utils/ERC1271InputGenerator.sol";

contract CoinbaseSmartWallet1271InputGeneratorTest is Test {
    CoinbaseSmartWalletFactory factory;
    CoinbaseSmartWallet implementation;
    CoinbaseSmartWallet deployedAccount;
    bytes[] owners;

    function setUp() public {
        implementation = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(implementation));
    }

    function testGetReplaySafeHashForDeployedAccount() public {
        owners.push(abi.encode(address(1)));
        deployedAccount = CoinbaseSmartWallet(payable(factory.createAccount(owners, 0)));

        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 replaySafeHash = deployedAccount.replaySafeHash(hash);
        ERC1271InputGenerator generator = new ERC1271InputGenerator(deployedAccount, hash, address(0), "");
        assertEq(bytes32(address(generator).code), replaySafeHash);
    }

    function testGetReplaySafeHashForUndeployedAccount() public {
        owners.push(abi.encode(address(1)));
        CoinbaseSmartWallet undeployedAccount = CoinbaseSmartWallet(payable(factory.getAddress(owners, 0)));
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedAccount,
            hash,
            address(factory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", owners, 0)
        );

        // This is now deployed.
        bytes32 replaySafeHash = undeployedAccount.replaySafeHash(hash);

        assertEq(bytes32(address(generator).code), replaySafeHash);
    }

    /// @notice Test replay safe hash with multiple owners
    function testGetReplaySafeHashWithMultipleOwners() public {
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
        owners.push(abi.encode(address(3)));
        deployedAccount = CoinbaseSmartWallet(payable(factory.createAccount(owners, 0)));

        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 replaySafeHash = deployedAccount.replaySafeHash(hash);
        ERC1271InputGenerator generator = new ERC1271InputGenerator(deployedAccount, hash, address(0), "");
        assertEq(bytes32(address(generator).code), replaySafeHash);
    }

    /// @notice Test with different nonce values
    function testGetReplaySafeHashWithDifferentNonces() public {
        owners.push(abi.encode(address(1)));
        
        // Create accounts with different nonces
        CoinbaseSmartWallet account0 = CoinbaseSmartWallet(payable(factory.createAccount(owners, 0)));
        CoinbaseSmartWallet account1 = CoinbaseSmartWallet(payable(factory.createAccount(owners, 1)));
        
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        
        bytes32 replaySafeHash0 = account0.replaySafeHash(hash);
        bytes32 replaySafeHash1 = account1.replaySafeHash(hash);
        
        // Different accounts should produce different replay-safe hashes
        assertTrue(replaySafeHash0 != replaySafeHash1);
        
        ERC1271InputGenerator generator0 = new ERC1271InputGenerator(account0, hash, address(0), "");
        ERC1271InputGenerator generator1 = new ERC1271InputGenerator(account1, hash, address(0), "");
        
        assertEq(bytes32(address(generator0).code), replaySafeHash0);
        assertEq(bytes32(address(generator1).code), replaySafeHash1);
    }

    /// @notice Test with zero hash
    function testGetReplaySafeHashWithZeroHash() public {
        owners.push(abi.encode(address(1)));
        deployedAccount = CoinbaseSmartWallet(payable(factory.createAccount(owners, 0)));

        bytes32 hash = bytes32(0);
        bytes32 replaySafeHash = deployedAccount.replaySafeHash(hash);
        ERC1271InputGenerator generator = new ERC1271InputGenerator(deployedAccount, hash, address(0), "");
        assertEq(bytes32(address(generator).code), replaySafeHash);
    }

    /// @notice Fuzz test for replay safe hash with various hashes
    function testFuzz_GetReplaySafeHash(bytes32 hash) public {
        owners.push(abi.encode(address(1)));
        deployedAccount = CoinbaseSmartWallet(payable(factory.createAccount(owners, 0)));

        bytes32 replaySafeHash = deployedAccount.replaySafeHash(hash);
        ERC1271InputGenerator generator = new ERC1271InputGenerator(deployedAccount, hash, address(0), "");
        assertEq(bytes32(address(generator).code), replaySafeHash);
    }

    /// @notice Fuzz test with various owner addresses for deployed accounts
    function testFuzz_GetReplaySafeHashForDeployedAccount(address owner, bytes32 hash) public {
        vm.assume(owner != address(0));
        owners.push(abi.encode(owner));
        deployedAccount = CoinbaseSmartWallet(payable(factory.createAccount(owners, 0)));

        bytes32 replaySafeHash = deployedAccount.replaySafeHash(hash);
        ERC1271InputGenerator generator = new ERC1271InputGenerator(deployedAccount, hash, address(0), "");
        assertEq(bytes32(address(generator).code), replaySafeHash);
    }

    /// @notice Test that undeployed account with passkey owner works correctly
    function testGetReplaySafeHashForUndeployedAccountWithPasskeyOwner() public {
        // Passkey owner (64 bytes - x and y coordinates)
        bytes32 x = bytes32(uint256(1));
        bytes32 y = bytes32(uint256(2));
        owners.push(abi.encode(x, y));
        
        CoinbaseSmartWallet undeployedAccount = CoinbaseSmartWallet(payable(factory.getAddress(owners, 0)));
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedAccount,
            hash,
            address(factory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", owners, 0)
        );

        bytes32 replaySafeHash = undeployedAccount.replaySafeHash(hash);
        assertEq(bytes32(address(generator).code), replaySafeHash);
    }
}


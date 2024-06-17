// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployFactoryScript is Script {
    address constant EXPECTED_IMPLEMENTATION = 0x000100Bf1DcF5C38Fe873f76B565d948ad12822E;
    address constant EXPECTED_FACTORY = 0x0BA5ED01C67936AfbEB2022E93dB179c24116976;

    function run() public {
        console2.log("Deploying on chain ID", block.chainid);

        address keyStore = 0xa3c95c6fb0151b42C29754FEF66b38dd6Eaa2950;
        address stateVerifier = 0x3aEC28C4a6fc29daE0B2c4b8b4a5e6C107Ac8391;

        address implementation = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWallet).creationCode,
            args: abi.encode(keyStore, stateVerifier),
            salt: 0xb4820a6446c87247f5c5f3bbabedea31e82b3e2f6b938e6c1a247beca70e1ef4
        });
        console2.log("implementation", implementation);
        assert(implementation == EXPECTED_IMPLEMENTATION);

        address factory = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWalletFactory).creationCode,
            args: abi.encode(EXPECTED_IMPLEMENTATION),
            salt: 0x40dcb98f297dc3a74c637cfbc07933a3fd4f525ccc2eaf17793da40291af6d57
        });
        console2.log("factory", factory);
        assert(factory == EXPECTED_FACTORY);
    }
}

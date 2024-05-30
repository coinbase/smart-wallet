// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployFactoryScript is Script {
    address constant EXPECTED_IMPLEMENTATION = 0x000300A87c7e7AbadB4a238Cf5E8EEb672B383Fd;
    address constant EXPECTED_FACTORY = 0x0BA5ED0533b6380fD30F341F6C9f9001517973ad;

    function run() public {
        console2.log("Deploying on chain ID", block.chainid);

        address keyStore = 0xa3c95c6fb0151b42C29754FEF66b38dd6Eaa2950;
        address stateVerifier = 0x3aEC28C4a6fc29daE0B2c4b8b4a5e6C107Ac8391;

        address implementation = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWallet).creationCode,
            args: abi.encode(keyStore, stateVerifier),
            salt: 0xf174dba890e12172364d26b184d3d7beb3ec791651a14e7f7bd40de599ead693
        });
        console2.log("implementation", implementation);
        assert(implementation == EXPECTED_IMPLEMENTATION);

        address factory = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWalletFactory).creationCode,
            args: abi.encode(EXPECTED_IMPLEMENTATION),
            salt: 0xe00c5c1cf17cfd0206dc93ea587c69a2edde7d2df9719e389b25998f551f2da6
        });
        console2.log("factory", factory);
        assert(factory == EXPECTED_FACTORY);
    }
}

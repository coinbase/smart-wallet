// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployFactoryScript is Script {
    // cast code 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7 --rpc-url https://mainnet.base.org
    bytes constant SAFE_SINGLETON_FACTORY_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    address constant EXPECTED_IMPLEMENTATION =
        0x000100abaad02f1cfC8Bbe32bD5a564817339E72;
    address constant EXPECTED_FACTORY =
        0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a;

    function run() public {
        // Set the deployer code if it's not already on the chain.
        if (SafeSingletonDeployer.SAFE_SINGLETON_FACTORY.code.length == 0) {
            vm.etch(
                SafeSingletonDeployer.SAFE_SINGLETON_FACTORY,
                SAFE_SINGLETON_FACTORY_CODE
            );
        }

        console2.log("Deploying on chain ID", block.chainid);
        address implementation = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWallet).creationCode,
            salt: 0x3438ae5ce1ff7750c1e09c4b28e2a04525da412f91561eb5b57729977f591fbb
        });
        console2.log("implementation", implementation);
        assert(implementation == EXPECTED_IMPLEMENTATION);
        address factory = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWalletFactory).creationCode,
            args: abi.encode(EXPECTED_IMPLEMENTATION),
            salt: 0x278d06dab87f67bb2d83470a70c8975a2c99872f290058fb43bcc47da5f0390c
        });
        console2.log("factory", factory);
        assert(factory == EXPECTED_FACTORY);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployFactoryScript is Script {
    address constant EXPECTED_IMPLEMENTATION = 0x00000110dCdEdC9581cb5eCB8467282f2926534d;
    address constant EXPECTED_FACTORY = 0xBA5ED110eFDBa3D005bfC882d75358ACBbB85842;

    function run() public {
        console2.log("Deploying on chain ID", block.chainid);
        address implementation = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWallet).creationCode,
            salt: 0x3771220e68256b8d5aa359fe953bf594dad1a5473239d1251256f0e5e7473b16
        });
        console2.log("implementation", implementation);
        assert(implementation == EXPECTED_IMPLEMENTATION);

        address factory = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWalletFactory).creationCode,
            args: abi.encode(EXPECTED_IMPLEMENTATION),
            salt: 0x0000000000000000000000000000000000000000e8448b6b950698874d6a35bd
        });
        console2.log("factory", factory);
        assert(factory == EXPECTED_FACTORY);
    }
}

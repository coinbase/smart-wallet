// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {IDPOracle} from "../src/guardians/IDPOracle.sol";
import {Verifier} from "../src/guardians/Verifier.sol";
import {ZKLogin} from "../src/guardians/ZKLogin.sol";

import {CoinbaseSmartWallet} from "../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployZkLoginPocScript is Script {
    function run() public {
        vm.startBroadcast();
        IDPOracle idpOracle = new IDPOracle();
        Verifier verifier = new Verifier();
        ZKLogin zkLogin = new ZKLogin({idpOracle_: address(idpOracle), verifier_: address(verifier)});

        console2.log("IDPOracle deployed at", address(idpOracle));
        console2.log("Verifier deployed at", address(verifier));
        console2.log("ZKLogin deployed at", address(zkLogin));

        CoinbaseSmartWallet coinbaseSmartWallet = new CoinbaseSmartWallet();
        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(address(coinbaseSmartWallet));
        console2.log("CoinbaseSmartWallet implementation deployed at", address(coinbaseSmartWallet));
        console2.log("CoinbaseSmartWalletFactory deployed at", address(factory));

        vm.stopBroadcast();
    }
}

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

        // Set the PK for the Google IDP
        console2.log("Google IDP address:", msg.sender);
        idpOracle.setPk({
            kid: "c7e04465649ffa606557650c7e65f0a87ae00fe8",
            pk: IDPOracle.Pk({
                n: hex"eff1fb028408181fab646221cfab9f4780a116990f06e76b3685db3c7b298ed324d4df1d6f53db15afafd725b43eff2e8e6fdec294102c9cfe2b1250cfcdfe7ae2203032a129673c59dfe57e346b47462aea9afb2477100ce378b7068c9e8f661df78540b90a588779865e1a429b3d4c4726fe3b0af0c2496d658a0e32a06cc8aed14ebe53e09d59b4a8cb8d94dfeb6b3b7e7db5341f0fc7fcae42b8224d8edc1b44817a19f26143b3ce0f47a21c602d91e41376e5b09ca4af3b0a1f4ac04b14d3973eca43e11fd001e84cb9ae247c819f77907c493def1906615f6962d4fbeb7921fc0987883feaf0e615765a8999b44e9632ee0f6bf55a7c156ece110ecdd5",
                e: hex"010001"
            })
        });

        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {Base64} from "solady/utils/Base64.sol";

import {IDPOracle} from "../src/guardians/IDPOracle.sol";
import {Verifier} from "../src/guardians/Verifier.sol";
import {ZKLogin} from "../src/guardians/ZKLogin.sol";

import {CoinbaseSmartWallet} from "../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployZkLoginPocScript is Script {
    struct IDPEntry {
        string kid;
        string nBase64;
        string eBase64;
    }

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

        // Set the PK for Google IDP
        IDPEntry[] memory googlePks = new IDPEntry[](2);
        googlePks[0] = IDPEntry({
            kid: "c37da75c9fbe18c2ce9125b9aa1f300dcb31e8d9",
            nBase64: "vUiHFY8O45dBoYLGipsgaVOk7rGpim6CK1iPG2zSt3sO9-09S9dB5nQdIelGye-mouQXaW5U7H8lZnv5wLJ8VSzquaSh3zJkbDq-Wvgas6U-FJaMy35kiExr5gUKUGPAIjI2sLASDbFD0vT_jxtg0ZRknwkexz_gZadZQ-iFEO7unjpE_zQnx8LhN-3a8dRf2B45BLY5J9aQJi4Csa_NHzl9Ym4uStYraSgwW93VYJwDJ3wKTvwejPvlW3n0hUifvkMke3RTqnSDIbP2xjtNmj12wdd-VUw47-cor5lMn7LG400G7lmI8rUSEHIzC7UyzEW7y15_uzuqvIkFVTLXlQ",
            eBase64: "AQAB"
        });

        googlePks[1] = IDPEntry({
            kid: "23f7a3583796f97129e5418f9b2136fcc0a96462",
            nBase64: "jb7Wtq9aDMpiXvHGCB5nrfAS2UutDEkSbK16aDtDhbYJhDWhd7vqWhFbnP0C_XkSxsqWJoku69y49EzgabEiUMf0q3X5N0pNvV64krviH2m9uLnyGP5GMdwZpjTXARK9usGgYZGuWhjfgTTvooKDUdqVQYvbrmXlblkM6xjbA8GnShSaOZ4AtMJCjWnaN_UaMD_vAXvOYj4SaefDMSlSoiI46yipFdggfoIV8RDg1jeffyre_8DwOWsGz7b2yQrL7grhYCvoiPrybKmViXqu-17LTIgBw6TDk8EzKdKzm33_LvxU7AKs3XWW_NvZ4WCPwp4gr7uw6RAkdDX_ZAn0TQ",
            eBase64: "AQAB"
        });

        for (uint256 i; i < googlePks.length; i++) {
            string memory kid = googlePks[i].kid;
            bytes memory n = Base64.decode(googlePks[i].nBase64);
            bytes memory e = Base64.decode(googlePks[i].eBase64);

            IDPOracle.Pk memory pk = IDPOracle.Pk({n: n, e: e});
            idpOracle.setPk(kid, pk);
            console2.log("Registered PK for kid", kid);
        }

        vm.stopBroadcast();
    }
}

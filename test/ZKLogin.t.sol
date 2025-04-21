// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Base64} from "solady/utils/Base64.sol";

import {Test, Vm, console2} from "forge-std/Test.sol";

import {MultiOwnable} from "../src/MultiOwnable.sol";
import {IDPOracle} from "../src/guardians/IDPOracle.sol";
import {Verifier} from "../src/guardians/Verifier.sol";
import {ZKLogin} from "../src/guardians/ZKLogin.sol";

contract ZKLoginTest is Test {
    struct IDPEntry {
        string kid;
        string nBase64;
        string eBase64;
    }

    IDPOracle idpOracle;
    ZKLogin zkLogin;
    address public google;

    function setUp() public {
        google = makeAddr("google");

        idpOracle = new IDPOracle();
        Verifier verifier = new Verifier();

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

        vm.startPrank(google);
        for (uint256 i; i < googlePks.length; i++) {
            string memory kid = googlePks[i].kid;
            bytes memory n = Base64.decode(googlePks[i].nBase64);
            bytes memory e = Base64.decode(googlePks[i].eBase64);

            IDPOracle.Pk memory pk = IDPOracle.Pk({n: n, e: e});
            idpOracle.setPk(kid, pk);
        }
        vm.stopPrank();

        zkLogin = new ZKLogin({idpOracle_: address(idpOracle), verifier_: address(verifier)});
    }

    function test_recoverAccount() public {
        address account = makeAddr("account");
        console2.log("Account:", account);

        // Constants for test data from Go test
        address ephOwner = 0x0cbE8d89B0ED8e575f029F856D6c818b02926ac0;
        string memory idpPubKeyNBase64 = Base64.encode({
            data: idpOracle.getPk(google, "23f7a3583796f97129e5418f9b2136fcc0a96462").n,
            fileSafe: true,
            noPadding: true
        });
        string memory jwtHeaderJson = '{"alg":"RS256","kid":"23f7a3583796f97129e5418f9b2136fcc0a96462","typ":"JWT"}';
        string memory jwtPayloadJson =
            '{"iss":"https://accounts.google.com","azp":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","aud":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","sub":"113282815992720230663","at_hash":"Z5sFXDjIjrLAVFHeVZzcZA","nonce":"HBTIKWFNIabRB1inoG1jsfrXHam0OMkTfJ2eOPXK4II","iat":1745225957,"exp":1745229557}';
        string memory jwtSignatureBase64 =
            "Dq3WcN5BITPpIqJxItEsSmiTTo81I6UfNB-9mbXAXLNhsMCcqOI54PtMXVEzIT6hh87yEpyJ4qhj-Fixxxma7_XFaKiwBrqwYIqyymdMhSapwkWXK4NLQO0NnP-e_BPtSDilUS1D_AJa7cZC93Pc0-cACa8pJIZPiwmygqmkwmHxZrWN23cjhZkwA3zorJ2ZzyRjgpOQOk9nX9kXs9A3FP096uWPjh2ICfNrVG8uEbo6FA_COBBfRR5Rql8ZkR80lUTaGAaHaHTS2ELd0c26qYRrvfBAGMMnn6Xij-TCp_jYhwDGBfIAmCtSuunN9xmbk2dRRI7DgXuHRH4XxSf1IA";
        string memory jwtRnd = "0xde75dbbf8c5bb88b0f30e821576202b065c33525a4f34528019f4e89ec0920";
        string memory userSalt = "0xcec61e0368523a044fc7b3138b65869aa4c58694f1fb4dd273873d87d24986";
        bytes32 zkAddr = 0x1791e23f7409cf97e74568b2b612f499d89f460998fc959b79fc9aa374b6c940;

        vm.prank(account);
        zkLogin.setZkAddr(zkAddr);

        // Generate proof via CLI
        {
            console2.log("Generating proof via CLI...");
            string[] memory proveCmd = new string[](22);
            proveCmd[0] = "zk/cli/bin/cli";
            proveCmd[1] = "prove";
            proveCmd[2] = "-c";
            proveCmd[3] = "zk/artifacts/circuit.bin";
            proveCmd[4] = "-pk";
            proveCmd[5] = "zk/artifacts/pk.bin";
            proveCmd[6] = "-ephPubKeyHex";
            proveCmd[7] = vm.toString(ephOwner);
            proveCmd[8] = "-idpPubKeyNBase64";
            proveCmd[9] = idpPubKeyNBase64;
            proveCmd[10] = "-jwtHeaderJson";
            proveCmd[11] = jwtHeaderJson;
            proveCmd[12] = "-jwtPayloadJson";
            proveCmd[13] = jwtPayloadJson;
            proveCmd[14] = "-jwtSignatureBase64";
            proveCmd[15] = jwtSignatureBase64;
            proveCmd[16] = "-jwtRndHex";
            proveCmd[17] = jwtRnd;
            proveCmd[18] = "-userSaltHex";
            proveCmd[19] = userSalt;
            proveCmd[20] = "-o";
            proveCmd[21] = "zk/artifacts/proof_test.bin";

            Vm.FfiResult memory result = vm.tryFfi(proveCmd);
            if (result.exitCode != 0) {
                console2.log("stdout:", vm.toString(result.stdout));
                console2.log("stderr:", vm.toString(result.stderr));
                revert("Proof generation failed");
            }
        }

        console2.log("Reading generated proof from file...");
        bytes memory proof = vm.readFileBinary("zk/artifacts/proof_test.bin");
        console2.log("Proof length:", proof.length);

        ZKLogin.Proof memory proof_ = this.parseProof(proof);

        // Mock the call to MultiOwnable.addOwnerAddress
        vm.mockCall({
            callee: account,
            data: abi.encodeCall(MultiOwnable.addOwnerAddress, (ephOwner)),
            returnData: abi.encode("")
        });

        vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerAddress, (ephOwner)));

        console2.log("Recovering account...");
        zkLogin.recoverAccount({
            account: account,
            zkAddr: zkAddr,
            idp: google,
            kid: "23f7a3583796f97129e5418f9b2136fcc0a96462",
            ephPubKey: abi.encodePacked(ephOwner),
            proof: proof_
        });

        console2.log("%s added as an owner of %s", vm.toString(ephOwner), vm.toString(account));
    }

    function parseProof(bytes calldata proof) external pure returns (ZKLogin.Proof memory proof_) {
        uint256 fpSize = 32;

        for (uint256 i; i < 8; i++) {
            proof_.proof[i] = abi.decode(proof[fpSize * i:fpSize * (i + 1)], (uint256));
        }

        uint32 commitmentCount = uint32(bytes4(proof[fpSize * 8:fpSize * 8 + 4]));
        require(commitmentCount == 1, "Invalid commitment count");

        for (uint256 i; i < 2 * commitmentCount; i++) {
            uint256 offset = fpSize * 8 + 4 + i * fpSize;
            proof_.commitments[i] = abi.decode(proof[offset:offset + fpSize], (uint256));
        }

        for (uint256 i; i < 2; i++) {
            uint256 offset = fpSize * 8 + 4 + 2 * commitmentCount * fpSize + i * fpSize;
            proof_.commitmentPok[i] = abi.decode(proof[offset:offset + fpSize], (uint256));
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// import {Base64} from "solady/utils/Base64.sol";

// import {Test, Vm, console2} from "forge-std/Test.sol";

// import {MultiOwnable} from "../src/MultiOwnable.sol";
// import {IDPOracle} from "../src/guardians/IDPOracle.sol";
// import {Verifier} from "../src/guardians/Verifier.sol";
// import {ZKLogin} from "../src/guardians/ZKLogin.sol";

// contract ZKLoginTest is Test {
//     ZKLogin zkLogin;

//     uint256 public constant MAX_ISS_LEN = 64;
//     uint256 public constant MAX_AUD_LEN = 80;
//     uint256 public constant MAX_SUB_LEN = 64;

//     address public google;

//     function setUp() public {
//         google = makeAddr("google");

//         IDPOracle idpOracle = new IDPOracle();
//         Verifier verifier = new Verifier();

//         vm.prank(google);
//         idpOracle.setPk({
//             kid: "1234567890",
//             pk: IDPOracle.Pk({
//                 n:
// hex"eff1fb028408181fab646221cfab9f4780a116990f06e76b3685db3c7b298ed324d4df1d6f53db15afafd725b43eff2e8e6fdec294102c9cfe2b1250cfcdfe7ae2203032a129673c59dfe57e346b47462aea9afb2477100ce378b7068c9e8f661df78540b90a588779865e1a429b3d4c4726fe3b0af0c2496d658a0e32a06cc8aed14ebe53e09d59b4a8cb8d94dfeb6b3b7e7db5341f0fc7fcae42b8224d8edc1b44817a19f26143b3ce0f47a21c602d91e41376e5b09ca4af3b0a1f4ac04b14d3973eca43e11fd001e84cb9ae247c819f77907c493def1906615f6962d4fbeb7921fc0987883feaf0e615765a8999b44e9632ee0f6bf55a7c156ece110ecdd5",
//                 e: hex"010001"
//             })
//         });

//         zkLogin = new ZKLogin({idpOracle_: address(idpOracle), verifier_: address(verifier)});
//     }

//     function test_recoverAccount() public {
//         address account = makeAddr("account");
//         console2.log("Account:", account);

//         address newOwner = makeAddr("newOwner");
//         console2.log("New owner:", newOwner);

//         string memory jwtHeaderJson = '{"alg":"RS256","typ":"JWT","kid":"1234567890"}';
//         string memory jwtPayloadJson;
//         bytes32 userSalt;
//         {
//             string memory nonce =
//                 string.concat('"', Base64.encode({data: abi.encode(newOwner), fileSafe: true, noPadding: true}),
// '"');
//             string memory iss = '"google.com"';
//             string memory aud = '"csw.com"';
//             string memory sub = '"xenoliss"';
//             jwtPayloadJson = string.concat('{"iss":', iss, ',"aud":', aud, ',"sub":', sub, ',"nonce":', nonce, "}");
//             userSalt = _userSalt({iss: bytes(iss), aud: bytes(aud), sub: bytes(sub)});

//             bytes32 zkAddr = _zkAddr({iss: bytes(iss), aud: bytes(aud), sub: bytes(sub), userSalt: userSalt});

//             vm.prank(account);
//             zkLogin.setZkAddr({zkAddr: zkAddr});
//         }

//         string memory jwtBase64;
//         bytes32 jwtHash;
//         {
//             string memory jwtHeaderBase64 = Base64.encode({data: bytes(jwtHeaderJson), fileSafe: true, noPadding:
// true});
//             string memory jwtPayloadBase64 =
//                 Base64.encode({data: bytes(jwtPayloadJson), fileSafe: true, noPadding: true});
//             jwtBase64 = string.concat(jwtHeaderBase64, ".", jwtPayloadBase64);
//             jwtHash = sha256(bytes(jwtBase64));
//         }

//         console2.log("Generating proof via CLI...");
//         string[] memory proveCmd = new string[](12);
//         proveCmd[0] = "zk/cli/bin/cli";
//         proveCmd[1] = "prove";
//         proveCmd[2] = "-c";
//         proveCmd[3] = "zk/artifacts/circuit.bin";
//         proveCmd[4] = "-pk";
//         proveCmd[5] = "zk/artifacts/pk.bin";
//         proveCmd[6] = "-jwt";
//         proveCmd[7] = jwtBase64;
//         proveCmd[8] = "-s";
//         proveCmd[9] = vm.toString(userSalt);
//         proveCmd[10] = "-o";
//         proveCmd[11] = "zk/artifacts/proof_test.bin";

//         Vm.FfiResult memory result = vm.tryFfi(proveCmd);
//         if (result.exitCode != 0) {
//             console2.log("stdout:", vm.toString(result.stdout));
//             console2.log("stderr:", vm.toString(result.stderr));
//             revert("Proof generation failed");
//         }

//         console2.log("Reading generated proof from file...");
//         bytes memory proof = vm.readFileBinary("zk/artifacts/proof_test.bin");
//         console2.log("Proof length:", proof.length);
//         console2.log("Proof:", vm.toString(proof));

//         ZKLogin.Proof memory proof_ = this.parseProof(proof);

//         vm.mockCall({
//             callee: account,
//             data: abi.encodeCall(MultiOwnable.addOwnerAddress, (newOwner)),
//             returnData: abi.encode("")
//         });

//         vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerAddress, (newOwner)));

//         console2.log("Recovering account...");
//         zkLogin.recoverAccount({
//             account: account,
//             idp: google,
//             jwtHash: jwtHash,
//             jwtHeaderJson: jwtHeaderJson,
//             jwtSignature:
// hex"52c30c5edc502974fc73efe2931b2d7510ec30431c624d9ea337ca9a12d0feee9ced104cc8c26c5efa482a53f6485dcff9e8f4eeadb155e84b87d3fd2eb06365911f30d1bb792d676c2babf1f571c2e50ee3daae40df06cfbf3e2b8aa073162caf1a9224796c83650f4318c5dc8db5d5c6f69def1cceb9016e76f91867288c8b1721e6be1a399857da2a853205e0dca27ac6728a1cbca433101ff1d66a19c4ad6008d819c9ff9dddc625dacfb31d4638c0846bb927f39c9e4e62f2cb762eec4c1f44a6422c15dd00c8ec64e54417f497c77f14f4a6b8c1f2d24a85332f6a406dfa485753c28034534cedb01f6e148ee697df0800026dba75ca47b89f08f7d283",
//             newOwner: abi.encode(newOwner),
//             proof: proof_
//         });

//         console2.log("%s added as an owner of %s", vm.toString(newOwner), vm.toString(account));
//     }

//     function _zkAddr(bytes memory iss, bytes memory aud, bytes memory sub, bytes32 userSalt)
//         public
//         pure
//         returns (bytes32 zkAddr)
//     {
//         bytes memory issBuf = new bytes(MAX_ISS_LEN);
//         bytes memory audBuf = new bytes(MAX_AUD_LEN);
//         bytes memory subBuf = new bytes(MAX_SUB_LEN);

//         for (uint256 i; i < iss.length; i++) {
//             issBuf[i] = iss[i];
//         }

//         for (uint256 i; i < aud.length; i++) {
//             audBuf[i] = aud[i];
//         }

//         for (uint256 i; i < sub.length; i++) {
//             subBuf[i] = sub[i];
//         }

//         bytes memory secretBytes = bytes.concat(issBuf, audBuf, subBuf, abi.encode(userSalt));
//         zkAddr = sha256(secretBytes);
//     }

//     function _userSalt(bytes memory iss, bytes memory aud, bytes memory sub) public pure returns (bytes32 userSalt) {
//         bytes memory SEED = hex"deadbeef";
//         bytes memory nonce = bytes.concat(SEED, iss, aud, sub);
//         userSalt = keccak256(nonce);
//     }

//     function parseProof(bytes calldata proof) external pure returns (ZKLogin.Proof memory proof_) {
//         uint256 fpSize = 32;

//         for (uint256 i; i < 8; i++) {
//             proof_.proof[i] = abi.decode(proof[fpSize * i:fpSize * (i + 1)], (uint256));
//         }

//         uint32 commitmentCount = uint32(bytes4(proof[fpSize * 8:fpSize * 8 + 4]));
//         require(commitmentCount == 1, "Invalid commitment count");

//         for (uint256 i; i < 2 * commitmentCount; i++) {
//             uint256 offset = fpSize * 8 + 4 + i * fpSize;
//             proof_.commitments[i] = abi.decode(proof[offset:offset + fpSize], (uint256));
//         }

//         for (uint256 i; i < 2; i++) {
//             uint256 offset = fpSize * 8 + 4 + 2 * commitmentCount * fpSize + i * fpSize;
//             proof_.commitmentPok[i] = abi.decode(proof[offset:offset + fpSize], (uint256));
//         }
//     }
// }

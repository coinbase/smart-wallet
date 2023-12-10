// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
// import {DaimoVerifier, Signature} from "lib/daimo/packages/contract/src/DaimoVerifier.sol";
import "solady/test/utils/TestPlus.sol";
import {SignatureCheckerLib} from "solady/src/utils/SignatureCheckerLib.sol";
import {Ownable} from "solady/src/auth/Ownable.sol";
import "p256-verifier/src/utils/Base64URL.sol";

import {Utils} from "./Utils.sol";
import {MockEntryPoint} from "./mocks/MockEntryPoint.sol";
import {MockERC4337Account} from "./mocks/MockERC4337Account.sol";
import {ERC4337Account} from "../src/ERC4337Account.sol";

contract ERC4337Test is Test, TestPlus {
    bytes p256VerifierCode =
        hex"60e06040523461001a57610012366100c7565b602081519101f35b600080fd5b6040810190811067ffffffffffffffff82111761003b57604052565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60e0810190811067ffffffffffffffff82111761003b57604052565b90601f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0910116810190811067ffffffffffffffff82111761003b57604052565b60a08103610193578060201161001a57600060409180831161018f578060601161018f578060801161018f5760a01161018c57815182810181811067ffffffffffffffff82111761015f579061013291845260603581526080356020820152833560203584356101ab565b15610156575060ff6001915b5191166020820152602081526101538161001f565b90565b60ff909161013e565b6024837f4e487b710000000000000000000000000000000000000000000000000000000081526041600452fd5b80fd5b5080fd5b5060405160006020820152602081526101538161001f565b909283158015610393575b801561038b575b8015610361575b6103585780519060206101dc818301938451906103bd565b1561034d57604051948186019082825282604088015282606088015260808701527fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f60a08701527fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551958660c082015260c081526102588161006a565b600080928192519060055afa903d15610345573d9167ffffffffffffffff831161031857604051926102b1857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8401160185610086565b83523d828585013e5b156102eb57828280518101031261018c5750015190516102e693929185908181890994099151906104eb565b061490565b807f4e487b7100000000000000000000000000000000000000000000000000000000602492526001600452fd5b6024827f4e487b710000000000000000000000000000000000000000000000000000000081526041600452fd5b6060916102ba565b505050505050600090565b50505050600090565b507fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325518310156101c4565b5082156101bd565b507fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325518410156101b6565b7fffffffff00000001000000000000000000000000ffffffffffffffffffffffff90818110801590610466575b8015610455575b61044d577f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8282818080957fffffffff00000001000000000000000000000000fffffffffffffffffffffffc0991818180090908089180091490565b505050600090565b50801580156103f1575082156103f1565b50818310156103ea565b7f800000000000000000000000000000000000000000000000000000000000000081146104bc577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0190565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b909192608052600091600160a05260a05193600092811580610718575b61034d57610516838261073d565b95909460ff60c05260005b600060c05112156106ef575b60a05181036106a1575050507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5957f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2969594939291965b600060c05112156105c7575050505050507fffffffff00000001000000000000000000000000ffffffffffffffffffffffff91506105c260a051610ca2565b900990565b956105d9929394959660a05191610a98565b9097929181928960a0528192819a6105f66080518960c051610722565b61060160c051610470565b60c0528061061b5750505050505b96959493929196610583565b969b5061067b96939550919350916001810361068857507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5937f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29693610952565b979297919060a05261060f565b6002036106985786938a93610952565b88938893610952565b600281036106ba57505050829581959493929196610583565b9197917ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0161060f575095508495849661060f565b506106ff6080518560c051610722565b8061070b60c051610470565b60c052156105215761052d565b5060805115610508565b91906002600192841c831b16921c1681018091116104bc5790565b8015806107ab575b6107635761075f91610756916107b3565b92919091610c42565b9091565b50507f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296907f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f590565b508115610745565b919082158061094a575b1561080f57507f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29691507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5906001908190565b7fb01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a917fffffffff00000001000000000000000000000000ffffffffffffffffffffffff808481600186090894817f94e82e0c1ed3bdb90743191a9c5bbf0d88fc827fd214cc5f0b5ec6ba27673d6981600184090893841561091b575050808084800993840994818460010994828088600109957f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29609918784038481116104bc5784908180867fffffffff00000001000000000000000000000000fffffffffffffffffffffffd0991818580090808978885038581116104bc578580949281930994080908935b93929190565b9350935050921560001461093b5761093291610b6d565b91939092610915565b50506000806000926000610915565b5080156107bd565b91949592939095811580610a90575b15610991575050831580610989575b61097a5793929190565b50600093508392508291508190565b508215610970565b85919294951580610a88575b610a78577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff968703918783116104bc5787838189850908938689038981116104bc5789908184840908928315610a5d575050818880959493928180848196099b8c9485099b8c920999099609918784038481116104bc5784908180867fffffffff00000001000000000000000000000000fffffffffffffffffffffffd0991818580090808978885038581116104bc578580949281930994080908929190565b965096505050509093501560001461093b5761093291610b6d565b9550509150915091906001908190565b50851561099d565b508015610961565b939092821580610b65575b61097a577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff908185600209948280878009809709948380888a0998818080808680097fffffffff00000001000000000000000000000000fffffffffffffffffffffffc099280096003090884808a7fffffffff00000001000000000000000000000000fffffffffffffffffffffffd09818380090898898603918683116104bc57888703908782116104bc578780969481809681950994089009089609930990565b508015610aa3565b919091801580610c3a575b610c2d577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff90818460020991808084800980940991817fffffffff00000001000000000000000000000000fffffffffffffffffffffffc81808088860994800960030908958280837fffffffff00000001000000000000000000000000fffffffffffffffffffffffd09818980090896878403918483116104bc57858503928584116104bc5785809492819309940890090892565b5060009150819081908190565b508215610b78565b909392821580610c9a575b610c8d57610c5a90610ca2565b9182917fffffffff00000001000000000000000000000000ffffffffffffffffffffffff80809581940980099009930990565b5050509050600090600090565b508015610c4d565b604051906020918281019183835283604083015283606083015260808201527fffffffff00000001000000000000000000000000fffffffffffffffffffffffd60a08201527fffffffff00000001000000000000000000000000ffffffffffffffffffffffff60c082015260c08152610d1a8161006a565b600080928192519060055afa903d15610d93573d9167ffffffffffffffff83116103185760405192610d73857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8401160185610086565b83523d828585013e5b156102eb57828280518101031261018c5750015190565b606091610d7c56fea2646970667358221220fa55558b04ced380e93d0a46be01bb895ff30f015c50c516e898c341cd0a230264736f6c63430008150033";
    ERC4337Account public account;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);
    bytes[] owners;
    bytes passkeyOwner =
        hex"d0266650cb64be790f59ad65381659583bfbf6d8338783af12f4c9f6cd70333f8224d6f6a871980a9f08df9ff70ba3531299e8da7e42a9e8e89b84fb1f53febe";

    function setUp() public {
        vm.etch(address(0xc2b78104907F722DABAc4C69f826a522B2754De4), p256VerifierCode);
        account = new ERC4337Account();

        owners.push(abi.encode(signer));
        owners.push(passkeyOwner);
        account.initialize(owners);
    }

    function testInitialize() public view {
        assert(account.isOwner(signer));
        assert(account.isOwner(passkeyOwner));
    }

    function testValidateSignatureWithPasskeySigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = SignatureCheckerLib.toEthSignedMessageHash(account.replaySafeHash(hash));
        bytes memory sig = abi.encode(
            Utils.rawSignatureToSignature({
                challenge: toSign,
                r: 114402223712652727003631532622572663093479626690071915344462720478540043027933,
                s: 12929371899131655946206150468148136699220952501717878658815701223816686794150
            })
        );

        bytes memory sigWithOwnerIndex = abi.encodePacked(uint8(1), sig);

        // check a valid signature
        bytes4 ret = account.isValidSignature(hash, sigWithOwnerIndex);
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testValidateSignatureWithPasskeySignerFailsWithWrongPubKey() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = SignatureCheckerLib.toEthSignedMessageHash(account.replaySafeHash(hash));
        bytes memory sig = abi.encode(
            Utils.rawSignatureToSignature({
                challenge: toSign,
                r: 114402223712652727003631532622572663093479626690071915344462720478540043027933,
                s: 12929371899131655946206150468148136699220952501717878658815701223816686794150
            })
        );
        bytes memory sigWithOwnerIndex = abi.encodePacked(uint8(2), sig);

        // check a valid signature
        vm.expectRevert();
        account.isValidSignature(hash, sigWithOwnerIndex);
    }

    function testValidateSignatureWithPasskeySignerFailsWithWrongBadSignature() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = SignatureCheckerLib.toEthSignedMessageHash(account.replaySafeHash(hash));
        bytes memory sig = abi.encode(
            Utils.rawSignatureToSignature({
                challenge: toSign,
                r: 114402223712652727003631532622572663093479626690071915344462720478540043027933,
                s: 1
            })
        );
        bytes memory sigWithOwnerIndex = abi.encodePacked(uint8(1), sig);

        // check a valid signature
        bytes4 ret = account.isValidSignature(hash, sigWithOwnerIndex);
        assertEq(ret, bytes4(0xffffffff));
    }

    function testValidateSignatureWithEOASigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = SignatureCheckerLib.toEthSignedMessageHash(account.replaySafeHash(hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes4 ret = account.isValidSignature(hash, abi.encodePacked(uint8(0), signature));
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testValidateSignatureWithEOASignerFailsWithWrongSigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xa12ce, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes4 ret = account.isValidSignature(hash, abi.encodePacked(uint8(0), signature));
        assertEq(ret, bytes4(0xffffffff));
    }

    /// taken from Solady and adapted ///

    function testExecute() public {
        vm.deal(address(account), 1 ether);
        vm.prank(signer);
        account.addOwner(abi.encode(address(this)));

        address target = address(new Target());
        bytes memory data = _randomBytes(111);
        account.execute(target, 123, abi.encodeWithSignature("setData(bytes)", data));
        assertEq(Target(target).datahash(), keccak256(data));
        assertEq(target.balance, 123);

        vm.prank(_randomNonZeroAddress());
        vm.expectRevert(Ownable.Unauthorized.selector);
        account.execute(target, 123, abi.encodeWithSignature("setData(bytes)", data));

        vm.expectRevert(abi.encodeWithSignature("TargetError(bytes)", data));
        account.execute(target, 123, abi.encodeWithSignature("revertWithTargetError(bytes)", data));
    }

    function testExecuteBatch() public {
        vm.deal(address(account), 1 ether);
        vm.prank(signer);
        account.addOwner(abi.encode(address(this)));

        ERC4337Account.Call[] memory calls = new ERC4337Account.Call[](2);
        calls[0].target = address(new Target());
        calls[1].target = address(new Target());
        calls[0].value = 123;
        calls[1].value = 456;
        calls[0].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(111));
        calls[1].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(222));

        account.executeBatch(calls);
        assertEq(Target(calls[0].target).datahash(), keccak256(_randomBytes(111)));
        assertEq(Target(calls[1].target).datahash(), keccak256(_randomBytes(222)));
        assertEq(calls[0].target.balance, 123);
        assertEq(calls[1].target.balance, 456);

        calls[1].data = abi.encodeWithSignature("revertWithTargetError(bytes)", _randomBytes(111));
        vm.expectRevert(abi.encodeWithSignature("TargetError(bytes)", _randomBytes(111)));
        account.executeBatch(calls);
    }

    function testExecuteBatch(uint256 r) public {
        account = new MockERC4337Account();
        account.initialize(owners);
        vm.prank(signer);
        account.addOwner(abi.encode(address(this)));
        vm.deal(address(account), 1 ether);

        unchecked {
            uint256 n = r & 3;
            ERC4337Account.Call[] memory calls = new ERC4337Account.Call[](n);

            for (uint256 i; i != n; ++i) {
                uint256 v = _random() & 0xff;
                calls[i].target = address(new Target());
                calls[i].value = v;
                calls[i].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(v));
            }

            bytes[] memory results;
            if (_random() & 1 == 0) {
                results = MockERC4337Account(payable(address(account))).executeBatch(_random(), calls);
            } else {
                results = account.executeBatch(calls);
            }

            assertEq(results.length, n);
            for (uint256 i; i != n; ++i) {
                uint256 v = calls[i].value;
                assertEq(Target(calls[i].target).datahash(), keccak256(_randomBytes(v)));
                assertEq(calls[i].target.balance, v);
                assertEq(abi.decode(results[i], (bytes)), _randomBytes(v));
            }
        }
    }

    struct _TestTemps {
        bytes32 userOpHash;
        address signer;
        uint256 privateKey;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 missingAccountFunds;
    }

    function testValidateUserOp() public {
        account = new ERC4337Account();
        _TestTemps memory t;
        t.userOpHash = keccak256("123");
        (t.signer, t.privateKey) = _randomSigner();
        (t.v, t.r, t.s) = vm.sign(t.privateKey, t.userOpHash);
        t.missingAccountFunds = 456;
        vm.deal(address(account), 1 ether);
        assertEq(address(account).balance, 1 ether);

        bytes[] memory k = new bytes[](1);
        k[0] = abi.encode(t.signer);

        account.initialize(k);

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        ERC4337Account.UserOperation memory userOp;
        // Success returns 0.
        userOp.signature = abi.encodePacked(uint8(0), t.r, t.s, t.v);
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 0);
        assertEq(address(ep).balance, t.missingAccountFunds);
        // Failure returns 1.
        userOp.signature = abi.encodePacked(uint8(0), t.r, bytes32(uint256(t.s) ^ 1), t.v);
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 1);
        assertEq(address(ep).balance, t.missingAccountFunds * 2);
        // Not entry point reverts.
        vm.expectRevert(Ownable.Unauthorized.selector);
        account.validateUserOp(userOp, t.userOpHash, t.missingAccountFunds);
    }

    function _randomBytes(uint256 seed) internal pure returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, seed)
            let r := keccak256(0x00, 0x20)
            if lt(byte(2, r), 0x20) {
                result := mload(0x40)
                let n := and(r, 0x7f)
                mstore(result, n)
                codecopy(add(result, 0x20), byte(1, r), add(n, 0x40))
                mstore(0x40, add(add(result, 0x40), n))
            }
        }
    }
}

contract Target {
    error TargetError(bytes data);

    bytes32 public datahash;

    bytes public data;

    function setData(bytes memory data_) public payable returns (bytes memory) {
        data = data_;
        datahash = keccak256(data_);
        return data_;
    }

    function revertWithTargetError(bytes memory data_) public payable {
        revert TargetError(data_);
    }

    function changeOwnerSlotValue(bool change) public payable {
        /// @solidity memory-safe-assembly
        assembly {
            if change { sstore(not(0x8b78c6d8), 0x112233) }
        }
    }
}

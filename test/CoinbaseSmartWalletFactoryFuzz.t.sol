// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {CoinbaseSmartWallet, MultiOwnable} from "../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract CoinbaseSmartWalletFactoryFuzzTest is Test {
    CoinbaseSmartWalletFactory factory;
    CoinbaseSmartWallet account;
    bytes[] owners;

    function setUp() public {
        account = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(account));
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
    }

    function encodeAddress(address _address) internal pure returns (bytes memory) {
        return abi.encode(_address);
    }

    function test_fuzzCreateAccountSetLimitOwners(uint16 _numberOfOwners, uint256 _value) public {
        vm.deal(address(this), _value);
        vm.assume(_numberOfOwners > 256 && _numberOfOwners <= 500);

        bytes[] memory _owners = new bytes[](uint256(_numberOfOwners));
        for (uint256 i = 0; i < _numberOfOwners; i++) {
            address ownerAddress = address(uint160(uint256(keccak256(abi.encodePacked(i, block.timestamp)))));
            _owners[i] = encodeAddress(ownerAddress);
        }

        uint256 nonce = uint256(keccak256(abi.encodePacked(block.timestamp)));
        address expectedAddress = factory.getAddress(_owners, nonce);
        CoinbaseSmartWallet a = factory.createAccount{value: _value}(_owners, nonce);
        assertEq(address(a), expectedAddress);
    }

    function test_fuzzCreateAccountSetOwners(uint256 _value, uint256 _nonce) public {
        vm.deal(address(this), _value);
        address expectedAddress = factory.getAddress(owners, _nonce);
        vm.expectCall(expectedAddress, abi.encodeCall(CoinbaseSmartWallet.initialize, (owners)));
        CoinbaseSmartWallet a = factory.createAccount{value: _value}(owners, _nonce);
        assert(a.isOwnerAddress(address(1)));
        assert(a.isOwnerAddress(address(2)));
    }

    function test_fuzzRevertNotEnoughFunds(uint256 _value, uint256 _balance, uint256 _nonce) public {
        vm.assume(_value > _balance);
        vm.deal(address(this), _balance);
        vm.expectRevert(bytes(""));
        factory.createAccount{value: _value}(owners, _nonce);
    }

    function test_fuzzSendsEtherIfAlreadyDeployed(uint256 _value, uint256 _nonce) public {
        vm.assume(_value >= 2);
        vm.assume(_value % 2 == 0);
        vm.deal(address(this), _value);
        uint256 callValue = _value / 2;
        CoinbaseSmartWallet a = factory.createAccount{value: callValue}(owners, _nonce);
        factory.createAccount{value: callValue}(owners, _nonce);
        assertEq(address(a).balance, _value);
    }

    function test_fuzzRevertsIfDuplicateOwners(uint256 _value, uint256 _nonce) public {
        vm.deal(address(this), _value);
        bytes memory duplicateOwner = abi.encode(address(2));
        owners.push(duplicateOwner);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.AlreadyOwner.selector, duplicateOwner));
        factory.createAccount{value: _value}(owners, _nonce);
    }

    function test_fuzzRevertsIfNoOwners(uint256 _value, uint256 _nonce) public {
        owners.pop();
        owners.pop();
        vm.deal(address(this), _value);
        vm.expectRevert(CoinbaseSmartWalletFactory.OwnerRequired.selector);
        factory.createAccount{value: _value}(owners, _nonce);
    }

    function test_fuzzRevertsIfLength32ButLargerThanAddress(uint256 _value, uint256 _nonce) public {
        vm.deal(address(this), _value);
        bytes memory badOwner = abi.encode(uint256(type(uint160).max) + 1);
        owners.push(badOwner);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.InvalidEthereumAddressOwner.selector, badOwner));
        factory.createAccount{value: _value}(owners, _nonce);
    }

    function test_fuzzCreateAccount_ReturnsPredeterminedAddress_WhenAccountAlreadyExists(uint256 _value, uint256 _nonce)
        public
    {
        vm.deal(address(this), _value);
        uint256 callValue = _value / 2;
        address p = factory.getAddress(owners, _nonce);
        CoinbaseSmartWallet a = factory.createAccount{value: callValue}(owners, _nonce);
        CoinbaseSmartWallet b = factory.createAccount{value: callValue}(owners, _nonce);
        assertEq(address(a), p);
        assertEq(address(a), address(b));
    }

    function test_FuzzSendExpectedFundsOnDeployment(uint256 _value, uint256 _nonce) public {
        vm.deal(address(this), _value);
        CoinbaseSmartWallet a = factory.createAccount{value: _value}(owners, _nonce);
        assertEq(address(a).balance, _value);
    }

    function test_fuzzImplementation_returnsExpectedAddress(address _account) public {
        CoinbaseSmartWalletFactory _factory = new CoinbaseSmartWalletFactory(_account);
        assertEq(_factory.implementation(), _account);
    }

    function test_fuzzInitCodeHash(address _account) public {
        CoinbaseSmartWalletFactory _factory = new CoinbaseSmartWalletFactory(_account);
        bytes32 execptedHash = LibClone.initCodeHashERC1967(_account);
        bytes32 factoryHash = _factory.initCodeHash();
        assertEq(factoryHash, execptedHash);
    }
}

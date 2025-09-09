// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {MockERC20} from "../../lib/solady/test/utils/mocks/MockERC20.sol";
import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {SmartWalletTestBase} from "../CoinbaseSmartWallet/SmartWalletTestBase.sol";

import {Static} from "../CoinbaseSmartWallet/Static.sol";
import {MockTarget} from "../mocks/MockTarget.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {console2} from "forge-std/Test.sol";

// Uniswap v4 imports
import {PoolManager} from "v4-core/PoolManager.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {PoolModifyLiquidityTest} from "v4-core/test/PoolModifyLiquidityTest.sol";
import {LiquidityAmounts} from "../../lib/v4-core/test/utils/LiquidityAmounts.sol";

/// forge-config: default.isolate = true
contract EndToEndTest is SmartWalletTestBase {
    using CurrencyLibrary for Currency;
    
    address eoaUser = address(0xe0a);

    MockERC20 usdc;
    MockERC20 weth;
    MockTarget target;
    CoinbaseSmartWalletFactory factory;
    
    // Uniswap v4 contracts
    IPoolManager poolManager;
    PoolSwapTest swapRouter;
    PoolModifyLiquidityTest modifyLiquidityRouter;
    PoolKey poolKey;
    
    uint160 constant SQRT_PRICE_1_1 = 79228162514264337593543950336; // sqrt(1) * 2^96
    uint160 constant MIN_PRICE_LIMIT = TickMath.MIN_SQRT_PRICE + 1;
    uint160 constant MAX_PRICE_LIMIT = TickMath.MAX_SQRT_PRICE - 1;

    function setUp() public override {
        vm.etch(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, Static.ENTRY_POINT_BYTES);

        CoinbaseSmartWallet implementation = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(implementation));

        signerPrivateKey = 0xa11ce;
        signer = vm.addr(signerPrivateKey);
        owners.push(abi.encode(signer));
        account = factory.createAccount(owners, 0);

        vm.deal(address(account), 100 ether);
        vm.deal(eoaUser, 100 ether);

        usdc = new MockERC20("USD Coin", "USDC", 6);
        weth = new MockERC20("Wrapped Ether", "WETH", 18);
        
        usdc.mint(address(account), 10000e6);
        usdc.mint(eoaUser, 10000e6);
        weth.mint(address(account), 100e18);
        weth.mint(eoaUser, 100e18);
        
        // For liquidity provision
        usdc.mint(address(this), 1000000e6);
        weth.mint(address(this), 1000e18);

        target = new MockTarget();
        
        poolManager = new PoolManager(address(this));
        swapRouter = new PoolSwapTest(poolManager);
        modifyLiquidityRouter = new PoolModifyLiquidityTest(poolManager);
        
        setupUniswapV4Pool();
    }

    function test_transfer_native() public {
        // Dust to avoid first-time transfer gas cost
        vm.deal(address(0x1234), 1 wei);
        usdc.mint(eoaUser, 1 wei);

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.execute, (address(0x1234), 1 ether, ""));
        UserOperation memory op = _getUserOpWithSignature();

        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_native Base Account calldata size:", handleOpsCalldata.length);

        vm.startSnapshotGas("e2e_transfer_native_baseAccount");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_transfer_native Base Account gas:", gas4337);

        console2.log("test_transfer_native EOA calldata size:", uint256(0));

        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_native_eoa");
        payable(address(0x1234)).transfer(1 ether);
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_transfer_native EOA gas:", gasEOA);
        console2.log("Gas overhead (4337 Base Account / EOA):", (gas4337 * 100) / gasEOA, "%");
    }

    function test_transfer_erc20() public {
        vm.deal(address(0x5678), 1 wei);
        usdc.mint(eoaUser, 1 wei);

        userOpCalldata = abi.encodeCall(
            CoinbaseSmartWallet.execute, (address(usdc), 0, abi.encodeCall(usdc.transfer, (address(0x5678), 100e6)))
        );
        UserOperation memory op = _getUserOpWithSignature();

        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_erc20 Base Account calldata size:", handleOpsCalldata.length);

        vm.startSnapshotGas("e2e_transfer_erc20_baseAccount");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 Base Account gas:", gas4337);

        bytes memory eoaCalldata = abi.encodeCall(usdc.transfer, (address(0x5678), 100e6));
        console2.log("test_transfer_erc20 EOA calldata size:", eoaCalldata.length);

        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_erc20_eoa");
        usdc.transfer(address(0x5678), 100e6);
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 EOA gas:", gasEOA);
        console2.log("Gas overhead (4337 Base Account / EOA):", (gas4337 * 100) / gasEOA, "%");
    }

    function test_swap() public {
        vm.prank(address(account));
        usdc.approve(address(swapRouter), type(uint256).max);
        vm.prank(address(account));
        weth.approve(address(swapRouter), type(uint256).max);
        
        vm.prank(eoaUser);
        usdc.approve(address(swapRouter), type(uint256).max);
        vm.prank(eoaUser);
        weth.approve(address(swapRouter), type(uint256).max);
        
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: true,
            amountSpecified: -1000e6, // Exact input: 1000 USDC
            sqrtPriceLimitX96: MIN_PRICE_LIMIT
        });
        bytes memory swapCalldata = abi.encodeCall(
            PoolSwapTest.swap,
            (poolKey, params, PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false}), "")
        );
        
        userOpCalldata = abi.encodeCall(
            CoinbaseSmartWallet.execute,
            (address(swapRouter), 0, swapCalldata)
        );
        UserOperation memory op = _getUserOpWithSignature();
        
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_swap Base Account calldata size:", handleOpsCalldata.length);
        
        vm.startSnapshotGas("e2e_swap_baseAccount");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_swap Base Account gas:", gas4337);
        
        console2.log("test_swap EOA calldata size:", swapCalldata.length);
        
        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_swap_eoa");
        swapRouter.swap(poolKey, params, PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false}), "");
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_swap EOA gas:", gasEOA);
        console2.log("Gas overhead (4337 Base Account / EOA):", (gas4337 * 100) / gasEOA, "%");
    }

    function _makeOpsArray(UserOperation memory op) internal pure returns (UserOperation[] memory) {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        return ops;
    }

    function _sign(UserOperation memory userOp) internal view override returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
    }
    
    function setupUniswapV4Pool() internal {
        Currency currency0;
        Currency currency1;
        
        if (address(usdc) < address(weth)) {
            currency0 = Currency.wrap(address(usdc));
            currency1 = Currency.wrap(address(weth));
        } else {
            currency0 = Currency.wrap(address(weth));
            currency1 = Currency.wrap(address(usdc));
        }
        
        poolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0))
        });
        
        // sqrtPriceX96 = sqrt(10^12) * 2^96 for USDC/WETH decimal adjustment
        uint160 sqrtPriceX96 = 79228162514264337593543950336 * 1e6;
        poolManager.initialize(poolKey, sqrtPriceX96);
        
        usdc.approve(address(modifyLiquidityRouter), type(uint256).max);
        weth.approve(address(modifyLiquidityRouter), type(uint256).max);
        
        IPoolManager.ModifyLiquidityParams memory params = IPoolManager.ModifyLiquidityParams({
            tickLower: -887220,
            tickUpper: 887220,
            liquidityDelta: 1000e6,
            salt: 0
        });
        
        modifyLiquidityRouter.modifyLiquidity(poolKey, params, "");
        
        usdc.approve(address(poolManager), type(uint256).max);
        weth.approve(address(poolManager), type(uint256).max);
    }
}

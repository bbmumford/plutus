// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PlutusEscrow} from "../PlutusEscrow.sol";
import {ProtocolRegistry} from "../ProtocolRegistry.sol";
import {IERC20} from "../interfaces/IERC20.sol";

/// @title MockERC20
/// @notice Minimal ERC20 for testing.
contract MockERC20 is IERC20 {
    string public name = "Mock USDC";
    string public symbol = "USDC";
    uint8 public decimals = 6;
    uint256 public override totalSupply;
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        require(allowance[from][msg.sender] >= amount, "not approved");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract PlutusEscrowTest is Test {
    MockERC20 token;
    ProtocolRegistry prc;
    PlutusEscrow escrow;

    address maintainer = address(0x1111);
    address buyerAddr = address(0x2222);
    address sellerAddr = address(0x3333);
    address arbitratorAddr = address(0x4444);

    uint256 constant ESCROW_AMOUNT = 100_000000; // $100 USDC (6 decimals)
    uint256 constant MAINTAINER_BPS = 100;       // 1%
    uint256 constant WITNESS_BPS = 25;           // 0.25%
    bytes32 constant PUB_KEY_HASH = bytes32(uint256(0xdeadbeef));

    function setUp() public {
        // Deploy mock token.
        token = new MockERC20();

        // Deploy PRC.
        prc = new ProtocolRegistry(
            maintainer,
            MAINTAINER_BPS,
            WITNESS_BPS,
            PUB_KEY_HASH
        );

        // Mint tokens to buyer.
        token.mint(buyerAddr, ESCROW_AMOUNT * 10);

        // Create escrow (timeout = current block + 100).
        bytes32[] memory witnessHashes = new bytes32[](2);
        witnessHashes[0] = bytes32(uint256(1));
        witnessHashes[1] = bytes32(uint256(2));

        escrow = new PlutusEscrow(
            address(prc),
            address(token),
            buyerAddr,
            sellerAddr,
            ESCROW_AMOUNT,
            block.number + 100,
            bytes32(0),
            witnessHashes
        );
    }

    function testConstructor() public view {
        assertEq(escrow.buyer(), buyerAddr);
        assertEq(escrow.seller(), sellerAddr);
        assertEq(escrow.amount(), ESCROW_AMOUNT);
        assertEq(escrow.maintainerPayout(), maintainer);
        assertEq(escrow.maintainerFeeBPS(), MAINTAINER_BPS);
        assertEq(escrow.witnessBPS(), WITNESS_BPS);
        assertEq(uint256(escrow.state()), uint256(PlutusEscrow.State.Pending));
    }

    function testFund() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        vm.stopPrank();

        assertEq(uint256(escrow.state()), uint256(PlutusEscrow.State.Funded));
        assertEq(token.balanceOf(address(escrow)), ESCROW_AMOUNT);
    }

    function testFundOnlyBuyer() public {
        vm.prank(sellerAddr);
        vm.expectRevert(PlutusEscrow.OnlyBuyer.selector);
        escrow.fund();
    }

    function testFundOnlyPending() public {
        // Fund once.
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        // Try to fund again.
        vm.expectRevert();
        escrow.fund();
        vm.stopPrank();
    }

    function testRelease() public {
        // Fund.
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();

        // Release.
        escrow.release();
        vm.stopPrank();

        assertEq(uint256(escrow.state()), uint256(PlutusEscrow.State.Released));

        // Check fee distribution.
        // Maintainer fee: 100_000000 * 100 / 10000 = 1_000000 (1%)
        // Witness fee: 100_000000 * 25 / 10000 = 250000 (0.25%)
        // Seller: 100_000000 - 1_000000 - 250000 = 98_750000
        uint256 expectedMaintainerFee = (ESCROW_AMOUNT * MAINTAINER_BPS) / 10000;
        uint256 expectedWitnessFee = (ESCROW_AMOUNT * WITNESS_BPS) / 10000;
        uint256 expectedSellerAmount = ESCROW_AMOUNT - expectedMaintainerFee - expectedWitnessFee;

        // Maintainer receives both maintainer fee and witness fee.
        assertEq(
            token.balanceOf(maintainer),
            expectedMaintainerFee + expectedWitnessFee
        );
        assertEq(token.balanceOf(sellerAddr), expectedSellerAmount);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    function testDispute() public {
        // Fund.
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();

        // Dispute.
        escrow.dispute(arbitratorAddr);
        vm.stopPrank();

        assertEq(uint256(escrow.state()), uint256(PlutusEscrow.State.Disputed));
        assertEq(escrow.arbitrator(), arbitratorAddr);
    }

    function testDisputeFromSeller() public {
        // Fund.
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        vm.stopPrank();

        // Seller disputes.
        vm.prank(sellerAddr);
        escrow.dispute(arbitratorAddr);

        assertEq(uint256(escrow.state()), uint256(PlutusEscrow.State.Disputed));
    }

    function testDisputeOnlyBuyerOrSeller() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        vm.stopPrank();

        vm.prank(arbitratorAddr);
        vm.expectRevert(PlutusEscrow.OnlyBuyerOrSeller.selector);
        escrow.dispute(arbitratorAddr);
    }

    function testSettle() public {
        // Fund + dispute.
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        escrow.dispute(arbitratorAddr);
        vm.stopPrank();

        // Settle: 60% buyer, 40% seller.
        vm.prank(arbitratorAddr);
        escrow.settle(60, 40);

        assertEq(uint256(escrow.state()), uint256(PlutusEscrow.State.Settled));

        // Check distribution.
        uint256 mFee = (ESCROW_AMOUNT * MAINTAINER_BPS) / 10000;
        uint256 wFee = (ESCROW_AMOUNT * WITNESS_BPS) / 10000;
        uint256 distributable = ESCROW_AMOUNT - mFee - wFee;
        uint256 buyerAmount = (distributable * 60) / 100;
        uint256 sellerAmount = distributable - buyerAmount;

        assertEq(token.balanceOf(maintainer), mFee + wFee);
        assertEq(token.balanceOf(buyerAddr), (ESCROW_AMOUNT * 10 - ESCROW_AMOUNT) + buyerAmount);
        assertEq(token.balanceOf(sellerAddr), sellerAmount);
    }

    function testSettleOnlyArbitrator() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        escrow.dispute(arbitratorAddr);
        vm.stopPrank();

        vm.prank(buyerAddr);
        vm.expectRevert(PlutusEscrow.OnlyArbitrator.selector);
        escrow.settle(50, 50);
    }

    function testSettleInvalidPercentages() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        escrow.dispute(arbitratorAddr);
        vm.stopPrank();

        vm.prank(arbitratorAddr);
        vm.expectRevert(PlutusEscrow.InvalidPercentages.selector);
        escrow.settle(60, 60);
    }

    function testRefundAfterTimeout() public {
        // Fund.
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        vm.stopPrank();

        // Advance past timeout.
        vm.roll(block.number + 101);

        // Refund.
        vm.prank(buyerAddr);
        escrow.refund();

        assertEq(uint256(escrow.state()), uint256(PlutusEscrow.State.Refunded));
        // Buyer gets full amount back (no fees on refund).
        assertEq(token.balanceOf(buyerAddr), ESCROW_AMOUNT * 10);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    function testRefundBeforeTimeout() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();

        vm.expectRevert(PlutusEscrow.TimeoutNotReached.selector);
        escrow.refund();
        vm.stopPrank();
    }

    function testRefundOnlyBuyer() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        vm.stopPrank();

        vm.roll(block.number + 101);

        vm.prank(sellerAddr);
        vm.expectRevert(PlutusEscrow.OnlyBuyer.selector);
        escrow.refund();
    }

    function testWitnessHashCount() public view {
        assertEq(escrow.witnessHashCount(), 2);
    }

    function testNoWitnessFeeWithoutHashes() public {
        // Create escrow with no witness hashes.
        bytes32[] memory noHashes = new bytes32[](0);
        PlutusEscrow escrowNoWitness = new PlutusEscrow(
            address(prc),
            address(token),
            buyerAddr,
            sellerAddr,
            ESCROW_AMOUNT,
            block.number + 100,
            bytes32(0),
            noHashes
        );

        // Fund and release.
        vm.startPrank(buyerAddr);
        token.approve(address(escrowNoWitness), ESCROW_AMOUNT);
        escrowNoWitness.fund();
        escrowNoWitness.release();
        vm.stopPrank();

        // Only maintainer fee, no witness fee.
        uint256 mFee = (ESCROW_AMOUNT * MAINTAINER_BPS) / 10000;
        uint256 expectedSeller = ESCROW_AMOUNT - mFee;

        assertEq(token.balanceOf(maintainer), mFee);
        assertEq(token.balanceOf(sellerAddr), expectedSeller);
    }

    function testFullSettleCycle100PercentBuyer() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        escrow.dispute(arbitratorAddr);
        vm.stopPrank();

        vm.prank(arbitratorAddr);
        escrow.settle(100, 0);

        uint256 mFee = (ESCROW_AMOUNT * MAINTAINER_BPS) / 10000;
        uint256 wFee = (ESCROW_AMOUNT * WITNESS_BPS) / 10000;
        uint256 distributable = ESCROW_AMOUNT - mFee - wFee;

        // Buyer gets back original balance minus escrow plus distributable.
        assertEq(token.balanceOf(buyerAddr), (ESCROW_AMOUNT * 10 - ESCROW_AMOUNT) + distributable);
        assertEq(token.balanceOf(sellerAddr), 0);
    }

    function testFullSettleCycle100PercentSeller() public {
        vm.startPrank(buyerAddr);
        token.approve(address(escrow), ESCROW_AMOUNT);
        escrow.fund();
        escrow.dispute(arbitratorAddr);
        vm.stopPrank();

        vm.prank(arbitratorAddr);
        escrow.settle(0, 100);

        uint256 mFee = (ESCROW_AMOUNT * MAINTAINER_BPS) / 10000;
        uint256 wFee = (ESCROW_AMOUNT * WITNESS_BPS) / 10000;
        uint256 distributable = ESCROW_AMOUNT - mFee - wFee;

        assertEq(token.balanceOf(sellerAddr), distributable);
    }
}

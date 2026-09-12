// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PlutusStorageEscrow} from "../PlutusStorageEscrow.sol";
import {ProtocolRegistry} from "../ProtocolRegistry.sol";
import {IERC20} from "../interfaces/IERC20.sol";

/// @title MockERC20
/// @notice Minimal ERC20 for storage-escrow testing.
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

contract PlutusStorageEscrowTest is Test {
    MockERC20 token;
    ProtocolRegistry prc;

    address maintainer = address(0x1111);
    address sellerAddr = address(0x2222);
    address replicatorAddr = address(0x3333);
    address challengerAddr = address(0x4444);

    uint256 constant TOTAL_FEE = 7_000_000; // $7 (for an easy 7-week duration)
    uint256 constant DURATION_WEEKS = 7;
    uint256 constant DURATION_SECS = DURATION_WEEKS * 7 days;
    uint256 constant REP_FACTOR = 3;
    bytes32 constant CID_HASH = keccak256("bafybeiexampleciddeadbeef");
    bytes32 constant PUB_KEY_HASH = bytes32(uint256(0xdeadbeef));

    function setUp() public {
        token = new MockERC20();
        prc = new ProtocolRegistry(
            maintainer,
            100, // maintainerFeeBPS — unused here but required
            25,
            PUB_KEY_HASH,
            bytes32(0),
            new bytes32[](0)
        );
        token.mint(sellerAddr, TOTAL_FEE * 10);
        token.mint(replicatorAddr, TOTAL_FEE * 10);
        token.mint(challengerAddr, 0); // ensure non-zero address, zero balance
    }

    /// @dev Helper: deploy an escrow with the seller approving fees and a future bond deadline.
    function _deploy() internal returns (PlutusStorageEscrow e) {
        vm.prank(sellerAddr);
        token.approve(type(uint256).max > 0 ? address(this) : address(0), 0); // noop, silence lint
        vm.prank(sellerAddr);
        // Calculate the to-be-deployed address so we can approve it. Foundry
        // provides computeCreateAddress for this; we use it by pre-computing.
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.prank(sellerAddr);
        token.approve(predicted, TOTAL_FEE);
        e = new PlutusStorageEscrow(
            address(prc),
            address(token),
            sellerAddr,
            replicatorAddr,
            CID_HASH,
            DURATION_SECS,
            REP_FACTOR,
            TOTAL_FEE,
            block.timestamp + 7 days
        );
    }

    function _bondReplicator(PlutusStorageEscrow e) internal {
        vm.startPrank(replicatorAddr);
        token.approve(address(e), e.bondAmount());
        e.bondReplicator();
        vm.stopPrank();
    }

    function testConstructorFundsTotalFee() public {
        PlutusStorageEscrow e = _deploy();
        assertEq(token.balanceOf(address(e)), TOTAL_FEE);
        assertEq(e.totalFee(), TOTAL_FEE);
        assertEq(e.weeksInDuration(), DURATION_WEEKS);
        assertEq(e.weeklyFee(), TOTAL_FEE / DURATION_WEEKS);
        assertEq(e.bondAmount(), TOTAL_FEE / 10);
        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Created));
    }

    function testReplicatorBondActivates() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);
        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Active));
        // Contract now holds fee + bond.
        assertEq(token.balanceOf(address(e)), TOTAL_FEE + e.bondAmount());
    }

    function testRefundIfNoBondBeforeDeadline() public {
        PlutusStorageEscrow e = _deploy();
        vm.warp(block.timestamp + 8 days);
        vm.prank(sellerAddr);
        e.refundUnbonded();
        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Refunded));
        assertEq(token.balanceOf(address(e)), 0);
    }

    function testRefundBeforeDeadlineReverts() public {
        PlutusStorageEscrow e = _deploy();
        vm.prank(sellerAddr);
        vm.expectRevert(PlutusStorageEscrow.BondDeadlineNotPassed.selector);
        e.refundUnbonded();
    }

    function testChallengeSuccessfulResponse() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        bytes32 nonce = keccak256("nonce-1");
        // Replicator's correct response = keccak256(piece || nonce).
        bytes memory piece = bytes("the plaintext piece bytes");
        bytes32 expected = keccak256(abi.encodePacked(piece, nonce));

        vm.prank(challengerAddr);
        e.openChallenge(nonce, expected);

        vm.prank(replicatorAddr);
        e.respond(expected);

        assertFalse(e.hasOpenChallenge());
        assertEq(e.missCount(), 0);
    }

    function testChallengeWrongResponseLogsMiss() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        bytes32 nonce = keccak256("nonce-wrong");
        bytes32 expected = keccak256("the correct answer");
        bytes32 wrong = keccak256("the wrong answer");

        vm.prank(challengerAddr);
        e.openChallenge(nonce, expected);

        vm.prank(replicatorAddr);
        e.respond(wrong);

        assertFalse(e.hasOpenChallenge());
        assertEq(e.missCount(), 1);
        assertEq(e.missCountThisWeek(), 1);
        assertEq(e.lastChallenger(), challengerAddr);
        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Active));
    }

    function testTwoMissesSlashesBond() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);
        uint256 sellerPre = token.balanceOf(sellerAddr);
        uint256 challengerPre = token.balanceOf(challengerAddr);

        // First miss.
        bytes32 n1 = keccak256("n1");
        vm.prank(challengerAddr);
        e.openChallenge(n1, keccak256("right1"));
        vm.prank(replicatorAddr);
        e.respond(keccak256("wrong1"));

        // Second miss (same week).
        bytes32 n2 = keccak256("n2");
        vm.prank(challengerAddr);
        e.openChallenge(n2, keccak256("right2"));
        vm.prank(replicatorAddr);
        e.respond(keccak256("wrong2"));

        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Slashed));
        assertEq(e.slashedAmount(), e.bondAmount());

        // Challenger got 10% of bond as bounty.
        uint256 expectedBounty = e.bondAmount() / 10;
        assertEq(token.balanceOf(challengerAddr) - challengerPre, expectedBounty);

        // Seller got the remaining bond + full unreleased fees back.
        uint256 expectedSellerRefund = (e.bondAmount() - expectedBounty) + TOTAL_FEE;
        assertEq(token.balanceOf(sellerAddr) - sellerPre, expectedSellerRefund);
    }

    function testExpireChallengeCountsAsMiss() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        bytes32 n = keccak256("expiry");
        vm.prank(challengerAddr);
        e.openChallenge(n, keccak256("expected"));

        // Jump past 24h.
        vm.warp(block.timestamp + 25 hours);

        // Anyone can expire.
        e.expireChallenge();
        assertEq(e.missCount(), 1);
        assertEq(e.missCountThisWeek(), 1);
    }

    function testRespondAfterWindowReverts() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        bytes32 n = keccak256("late");
        bytes32 expected = keccak256("correct");
        vm.prank(challengerAddr);
        e.openChallenge(n, expected);

        vm.warp(block.timestamp + 25 hours);

        vm.prank(replicatorAddr);
        vm.expectRevert(PlutusStorageEscrow.ChallengeWindowClosed.selector);
        e.respond(expected);
    }

    function testWeeklyReleasePaysReplicator() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        uint256 pre = token.balanceOf(replicatorAddr);
        vm.warp(block.timestamp + 7 days);
        // Anyone can call releaseWeekly.
        e.releaseWeekly();
        uint256 post = token.balanceOf(replicatorAddr);
        assertEq(post - pre, e.weeklyFee());
        assertEq(e.lastReleaseWeek(), 1);
        assertEq(e.missCountThisWeek(), 0);
    }

    function testFullDurationCompletes() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        for (uint256 i = 0; i < DURATION_WEEKS; i++) {
            vm.warp(block.timestamp + 7 days);
            e.releaseWeekly();
        }
        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Completed));
        assertEq(e.lastReleaseWeek(), DURATION_WEEKS);

        // Replicator has received the full weekly-fee stream. Bond is still
        // locked until they call withdrawBond (see testWithdrawBondAfterCompletion).
        uint256 afterWeeklies = TOTAL_FEE * 10 - e.bondAmount() + e.weeklyFee() * DURATION_WEEKS;
        assertEq(token.balanceOf(replicatorAddr), afterWeeklies);

        // After withdrawBond, the replicator balance reaches TOTAL_FEE*10 + fees
        // (bond returned, so the bond-escrowed amount no longer counts against them).
        vm.prank(replicatorAddr);
        e.withdrawBond();
        assertEq(
            token.balanceOf(replicatorAddr),
            TOTAL_FEE * 10 + e.weeklyFee() * DURATION_WEEKS
        );
        // Contract fully drained (no dust because TOTAL_FEE=7e6 divides 7 evenly).
        assertEq(token.balanceOf(address(e)), 0);
    }

    function testReleaseBeforeWeekReverts() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);
        vm.expectRevert(PlutusStorageEscrow.NoWeeklyReleaseReady.selector);
        e.releaseWeekly();
    }

    function testOnlyReplicatorCanBond() public {
        PlutusStorageEscrow e = _deploy();
        vm.prank(challengerAddr);
        vm.expectRevert(PlutusStorageEscrow.OnlyReplicator.selector);
        e.bondReplicator();
    }

    function testCannotOpenTwoChallengesAtOnce() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);
        vm.prank(challengerAddr);
        e.openChallenge(keccak256("n"), keccak256("h"));
        vm.prank(challengerAddr);
        vm.expectRevert(PlutusStorageEscrow.ChallengeAlreadyOpen.selector);
        e.openChallenge(keccak256("n2"), keccak256("h2"));
    }

    function testMissCountResetsEachWeek() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        // One miss in week 1.
        vm.prank(challengerAddr);
        e.openChallenge(keccak256("n"), keccak256("expected"));
        vm.prank(replicatorAddr);
        e.respond(keccak256("wrong"));
        assertEq(e.missCountThisWeek(), 1);

        // Release week → reset.
        vm.warp(block.timestamp + 7 days);
        e.releaseWeekly();
        assertEq(e.missCountThisWeek(), 0);
        // Total miss count does NOT reset.
        assertEq(e.missCount(), 1);
    }

    /// @notice Slash with a non-divisible totalFee must refund every last wei
    ///         including the integer-division dust that would otherwise be
    ///         stranded. Regression for the Fix-2 dust-loss bug.
    /// @dev Params: totalFee = 1007, weeksInDuration = 7 → weeklyFee = 143,
    ///      weeklyFee * weeksInDuration = 1001, stranded dust = 6 wei.
    ///      With the fix, a slash at week 0 must refund the full 1007 wei
    ///      of unreleased fees (plus the bond minus bounty) to the seller.
    function testSlashRefundIncludesTruncationDust() public {
        // Rebuild a fresh escrow with non-divisible totalFee.
        uint256 totalFeeOdd = 1007; // not divisible by 7
        uint256 weeks_ = 7;
        uint256 duration = weeks_ * 7 days;

        vm.prank(sellerAddr);
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.prank(sellerAddr);
        token.approve(predicted, totalFeeOdd);
        PlutusStorageEscrow e = new PlutusStorageEscrow(
            address(prc),
            address(token),
            sellerAddr,
            replicatorAddr,
            CID_HASH,
            duration,
            REP_FACTOR,
            totalFeeOdd,
            block.timestamp + 7 days
        );
        _bondReplicator(e);

        uint256 sellerPre = token.balanceOf(sellerAddr);

        // Two misses in the same week → slash.
        vm.prank(challengerAddr);
        e.openChallenge(keccak256("dust-n1"), keccak256("dust-r1"));
        vm.prank(replicatorAddr);
        e.respond(keccak256("dust-wrong1"));
        vm.prank(challengerAddr);
        e.openChallenge(keccak256("dust-n2"), keccak256("dust-r2"));
        vm.prank(replicatorAddr);
        e.respond(keccak256("dust-wrong2"));

        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Slashed));

        // Contract balance must be ZERO (modulo the bounty paid to
        // challenger). No dust left behind.
        uint256 bounty = e.bondAmount() / 10;
        uint256 expectedSellerRefund = (e.bondAmount() - bounty) + totalFeeOdd;
        assertEq(token.balanceOf(sellerAddr) - sellerPre, expectedSellerRefund);
        assertEq(token.balanceOf(address(e)), 0, "dust stranded in contract");
    }

    /// @notice Replicator can reclaim their bond after normal completion.
    ///         Regression for the Fix-5 missing-bond-return bug.
    function testWithdrawBondAfterCompletion() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);

        for (uint256 i = 0; i < DURATION_WEEKS; i++) {
            vm.warp(block.timestamp + 7 days);
            e.releaseWeekly();
        }
        assertEq(uint256(e.status()), uint256(PlutusStorageEscrow.Status.Completed));

        uint256 replicatorPre = token.balanceOf(replicatorAddr);
        vm.prank(replicatorAddr);
        e.withdrawBond();
        assertEq(token.balanceOf(replicatorAddr) - replicatorPre, e.bondAmount());
        // Contract balance must be zero: fees fully paid out + bond returned.
        assertEq(token.balanceOf(address(e)), 0);

        // Second call reverts (idempotent guard).
        vm.prank(replicatorAddr);
        vm.expectRevert(PlutusStorageEscrow.BondAlreadyWithdrawn.selector);
        e.withdrawBond();
    }

    /// @notice Non-replicators cannot withdraw the bond.
    function testWithdrawBondOnlyByReplicator() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);
        for (uint256 i = 0; i < DURATION_WEEKS; i++) {
            vm.warp(block.timestamp + 7 days);
            e.releaseWeekly();
        }
        vm.prank(challengerAddr);
        vm.expectRevert(PlutusStorageEscrow.OnlyReplicator.selector);
        e.withdrawBond();
    }

    /// @notice Cannot withdraw the bond while the contract is Active.
    function testWithdrawBondRejectedWhileActive() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);
        vm.prank(replicatorAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                PlutusStorageEscrow.InvalidStatus.selector,
                PlutusStorageEscrow.Status.Active,
                PlutusStorageEscrow.Status.Completed
            )
        );
        e.withdrawBond();
    }

    function testGetPinStatusView() public {
        PlutusStorageEscrow e = _deploy();
        _bondReplicator(e);
        (
            PlutusStorageEscrow.Status s,
            uint256 w,
            uint256 mc,
            uint256 mctw,
            uint256 slashed,
            uint256 endT
        ) = e.getPinStatus();
        assertEq(uint256(s), uint256(PlutusStorageEscrow.Status.Active));
        assertEq(w, 0);
        assertEq(mc, 0);
        assertEq(mctw, 0);
        assertEq(slashed, 0);
        assertEq(endT, e.endTime());
    }
}

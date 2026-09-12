// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ProtocolRegistry} from "../ProtocolRegistry.sol";
import {IERC20} from "../interfaces/IERC20.sol";

/// @notice Minimal ERC20 stub used by distributeWindow tests. Tracks balances
///         in a local mapping and mints to the pool via `mint`. Returns true
///         on transfer so SafeERC20's "returned value" branch fires.
contract MockERC20 is IERC20 {
    string public constant name = "Mock";
    string public constant symbol = "MCK";
    uint8 public constant decimals = 18;
    uint256 public override totalSupply;
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    function mint(address to, uint256 value) external {
        balanceOf[to] += value;
        totalSupply += value;
    }

    function transfer(address to, uint256 value) external override returns (bool) {
        require(balanceOf[msg.sender] >= value, "MOCK: balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external override returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= value, "MOCK: allowance");
        require(balanceOf[from] >= value, "MOCK: balance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external override returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
}

contract ProtocolRegistryTest is Test {
    ProtocolRegistry prc;

    address maintainer = address(0x1111);
    uint256 constant MAINTAINER_BPS = 100;
    uint256 constant WITNESS_BPS = 25;
    bytes32 constant PUB_KEY_HASH = bytes32(uint256(0xcafebabe));

    bytes32 manifestHash = bytes32(0);
    bytes32[] emptyAdapters;

    bytes32 constant CHAIN_ID = keccak256("polygon");

    // Events re-declared for expectEmit.
    event WindowDistributed(
        bytes32 indexed chainID,
        uint64 indexed windowID,
        bytes32 attestationLogRoot,
        uint256 payoutCount
    );
    event DistributionDisputed(
        bytes32 indexed chainID,
        uint64 indexed windowID,
        address indexed attester
    );

    function setUp() public {
        prc = new ProtocolRegistry(
            maintainer,
            MAINTAINER_BPS,
            WITNESS_BPS,
            PUB_KEY_HASH,
            manifestHash,
            emptyAdapters
        );
    }

    function testProtocolID() public view {
        assertEq(prc.protocolID(), "plutus-v1");
    }

    function testImmutableFields() public view {
        assertEq(prc.maintainerPayout(), maintainer);
        assertEq(prc.maintainerFeeBPS(), MAINTAINER_BPS);
        assertEq(prc.witnessBPS(), WITNESS_BPS);
        assertEq(prc.maintainerPubKeyHash(), PUB_KEY_HASH);
    }

    function testRegisterApp() public {
        bytes32 appHash = keccak256("mercury-v1");
        prc.registerApp(appHash);
        assertTrue(prc.registeredApps(appHash));
    }

    function testUnregisteredApp() public view {
        bytes32 appHash = keccak256("unknown-app");
        assertFalse(prc.registeredApps(appHash));
    }

    function testUnregisteredAdapter() public view {
        bytes32 adapterHash = bytes32(uint256(0x1234));
        assertFalse(prc.isApprovedAdapter(adapterHash));
    }

    function testConstructorRejectsHighMaintainerFee() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolRegistry.FeeTooHigh.selector,
                "maintainerFeeBPS",
                uint256(501),
                uint256(500)
            )
        );
        new ProtocolRegistry(maintainer, 501, WITNESS_BPS, PUB_KEY_HASH, manifestHash, emptyAdapters);
    }

    function testConstructorRejectsHighWitnessFee() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolRegistry.FeeTooHigh.selector,
                "witnessBPS",
                uint256(101),
                uint256(100)
            )
        );
        new ProtocolRegistry(maintainer, MAINTAINER_BPS, 101, PUB_KEY_HASH, manifestHash, emptyAdapters);
    }

    function testConstructorRejectsZeroAddress() public {
        vm.expectRevert(ProtocolRegistry.ZeroAddress.selector);
        new ProtocolRegistry(address(0), MAINTAINER_BPS, WITNESS_BPS, PUB_KEY_HASH, manifestHash, emptyAdapters);
    }

    function testMaxAllowedFees() public {
        ProtocolRegistry maxPRC = new ProtocolRegistry(
            maintainer,
            500,
            100,
            PUB_KEY_HASH,
            manifestHash,
            emptyAdapters
        );
        assertEq(maxPRC.maintainerFeeBPS(), 500);
        assertEq(maxPRC.witnessBPS(), 100);
    }

    function testMultipleAppRegistrations() public {
        bytes32 app1 = keccak256("app1");
        bytes32 app2 = keccak256("app2");
        bytes32 app3 = keccak256("app3");

        prc.registerApp(app1);
        prc.registerApp(app2);
        prc.registerApp(app3);

        assertTrue(prc.registeredApps(app1));
        assertTrue(prc.registeredApps(app2));
        assertTrue(prc.registeredApps(app3));
    }

    function testConstructorApprovedAdapters() public {
        bytes32 hash1 = keccak256("adapter1");
        bytes32 hash2 = keccak256("adapter2");
        bytes32[] memory adapters = new bytes32[](2);
        adapters[0] = hash1;
        adapters[1] = hash2;
        ProtocolRegistry prc2 = new ProtocolRegistry(maintainer, 100, 25, PUB_KEY_HASH, bytes32(0), adapters);
        assertTrue(prc2.isApprovedAdapter(hash1));
        assertTrue(prc2.isApprovedAdapter(hash2));
        assertFalse(prc2.isApprovedAdapter(keccak256("unknown")));
    }

    // --- distributeWindow tests --------------------------------------------

    function testDistributeWindow_HappyPath() public {
        MockERC20 token = new MockERC20();
        // Pool = this contract. Mint into this test contract so it acts as the
        // distributor submitter; transfer out via PRC's safeTransfer requires
        // PRC itself to hold the balance (SafeERC20.transfer is msg.sender
        // = PRC). So mint to PRC directly.
        token.mint(address(prc), 1_000 ether);

        address[] memory recipients = new address[](2);
        recipients[0] = address(0xAAAA);
        recipients[1] = address(0xBBBB);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 100 ether;
        amounts[1] = 200 ether;

        bytes32 root = keccak256("attestation-log-root-v1");
        uint64 windowID = 1000;

        vm.expectEmit(true, true, false, true, address(prc));
        emit WindowDistributed(CHAIN_ID, windowID, root, 2);
        prc.distributeWindow(CHAIN_ID, windowID, root, address(token), recipients, amounts);

        assertEq(prc.distributedWindows(CHAIN_ID, windowID), root, "root not written");
        assertEq(token.balanceOf(address(0xAAAA)), 100 ether, "recipient 0 payout");
        assertEq(token.balanceOf(address(0xBBBB)), 200 ether, "recipient 1 payout");
    }

    function testDistributeWindow_DuplicateReverts() public {
        MockERC20 token = new MockERC20();
        token.mint(address(prc), 1_000 ether);

        address[] memory recipients = new address[](1);
        recipients[0] = address(0xAAAA);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10 ether;

        bytes32 root = keccak256("root-A");
        uint64 windowID = 42;

        prc.distributeWindow(CHAIN_ID, windowID, root, address(token), recipients, amounts);

        // Second call with same (chainID, windowID) must revert, regardless of
        // whether the attacker supplies a different root or payout set.
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolRegistry.WindowAlreadyDistributed.selector,
                CHAIN_ID,
                windowID
            )
        );
        prc.distributeWindow(CHAIN_ID, windowID, keccak256("root-B"), address(token), recipients, amounts);
    }

    function testDistributeWindow_EmptyRootReverts() public {
        MockERC20 token = new MockERC20();
        token.mint(address(prc), 1_000 ether);

        address[] memory recipients = new address[](1);
        recipients[0] = address(0xAAAA);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10 ether;

        vm.expectRevert(ProtocolRegistry.RootRequired.selector);
        prc.distributeWindow(CHAIN_ID, 7, bytes32(0), address(token), recipients, amounts);
    }

    function testDistributeWindow_LengthMismatchReverts() public {
        MockERC20 token = new MockERC20();
        token.mint(address(prc), 1_000 ether);

        address[] memory recipients = new address[](2);
        recipients[0] = address(0xAAAA);
        recipients[1] = address(0xBBBB);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10 ether;

        vm.expectRevert(ProtocolRegistry.LengthMismatch.selector);
        prc.distributeWindow(CHAIN_ID, 8, keccak256("root"), address(token), recipients, amounts);
    }

    // --- disputeDistribution tests ----------------------------------------

    /// @dev Build a sorted-pair Merkle root over two leaves.
    function _pairRoot(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function testDisputeDistribution_ValidProofEmits() public {
        // Build a 2-leaf tree: leaf0 + leaf1 → root.
        bytes32 leaf0 = keccak256("attestation-0");
        bytes32 leaf1 = keccak256("attestation-1");
        bytes32 root = _pairRoot(leaf0, leaf1);

        // Land the window with the constructed root.
        MockERC20 token = new MockERC20();
        token.mint(address(prc), 1_000 ether);
        address[] memory recipients = new address[](1);
        recipients[0] = address(0xAAAA);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;
        uint64 windowID = 777;
        prc.distributeWindow(CHAIN_ID, windowID, root, address(token), recipients, amounts);

        // Proof for leaf0 is just [leaf1]; the verifier sorts the pair before
        // hashing, matching OZ MerkleProof.verify semantics.
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        address attester = address(0xF00D);
        vm.expectEmit(true, true, true, false, address(prc));
        emit DistributionDisputed(CHAIN_ID, windowID, attester);
        vm.prank(attester);
        prc.disputeDistribution(CHAIN_ID, windowID, leaf0, proof);
    }

    function testDisputeDistribution_InvalidProofReverts() public {
        bytes32 leaf0 = keccak256("attestation-0");
        bytes32 leaf1 = keccak256("attestation-1");
        bytes32 root = _pairRoot(leaf0, leaf1);

        MockERC20 token = new MockERC20();
        token.mint(address(prc), 1_000 ether);
        address[] memory recipients = new address[](1);
        recipients[0] = address(0xAAAA);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;
        uint64 windowID = 778;
        prc.distributeWindow(CHAIN_ID, windowID, root, address(token), recipients, amounts);

        // Garbage proof must be rejected.
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = keccak256("not-a-sibling");

        vm.expectRevert(ProtocolRegistry.ProofInvalid.selector);
        prc.disputeDistribution(CHAIN_ID, windowID, leaf0, badProof);
    }

    function testDisputeDistribution_WindowNotDistributedReverts() public {
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolRegistry.WindowNotDistributed.selector,
                CHAIN_ID,
                uint64(999)
            )
        );
        prc.disputeDistribution(CHAIN_ID, 999, keccak256("leaf"), proof);
    }
}

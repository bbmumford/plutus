package adapter

import (
	"math/big"
)

// CurrencyAdapter defines the interface that every chain-specific adapter must implement.
// Adapters handle all chain-specific logic: escrow construction, funding, release,
// dispute, settlement, and state queries.
type CurrencyAdapter interface {
	// Chain identification.
	ChainID() string
	Currency() string
	Symbol() string

	// Escrow lifecycle.
	ConstructEscrow(params EscrowParams) (*UnsignedTx, error)
	FundEscrow(escrowAddr string, amount *big.Int) (*UnsignedTx, error)
	ReleaseEscrow(escrowAddr string, params ReleaseParams) (*UnsignedTx, error)
	DisputeEscrow(escrowAddr string, params DisputeParams) (*UnsignedTx, error)
	SettleWithRuling(escrowAddr string, ruling Ruling) (*UnsignedTx, error)
	RefundAfterTimeout(escrowAddr string) (*UnsignedTx, error)

	// Query.
	EscrowState(escrowAddr string) (*EscrowState, error)
	Balance(addr string) (*big.Int, error)

	// Fee calculation: the breakdown of a positive amount under opts, refused when
	// an option exceeds its role's BPS cap or the roles together exceed the
	// combined cap. The parts always sum to the amount.
	CalculateFees(amount *big.Int, opts FeeOptions) (FeeBreakdown, error)
}

// EscrowParams contains the parameters for constructing a new escrow.
type EscrowParams struct {
	Buyer                 string   // buyer's chain address
	Seller                string   // seller's chain address
	Amount                *big.Int // escrow amount in smallest denomination
	Currency              string   // currency symbol (e.g., "USDC")
	TimeoutSeconds        uint64   // escrow timeout in seconds
	ArbitratorAddr        string   // optional arbitrator address
	PRCAddress            string   // Protocol Registry Contract address on this chain
	WitnessHashes         [][]byte // optional witness attestation hashes
	ReceiptHash           []byte   // optional service receipt hash
	ServiceProviderBPS    uint32   // service provider fee in basis points (max 200)
	ServiceProviderPayout string   // service provider payout address
	ArbitratorBPS         uint32   // arbitrator fee in basis points (max 300)

	// ArbitratorPayout is the chain-native address that receives the
	// arbitrator fee when the escrow is settled via ruling. Optional —
	// adapters that cannot route the fee (no address) absorb it into the
	// recipient output. On EVM this would be the arbitrator's 0x address;
	// on BTC the arbitrator's bech32 payout address.
	ArbitratorPayout string

	// WitnessPayout is the chain-native address that receives the witness
	// fee on release. Optional — adapters absorb the fee into the recipient
	// when empty.
	WitnessPayout string
}

// FeeBreakdown contains the deterministic fee calculation result.
// All values use big.Int for precision with arbitrary token decimals.
//
// WitnessFee is the aggregate witness fee (kept for backwards compatibility
// with adapters and audits that treat witnesses as a single payee).
// WitnessFees, when populated, contains the per-witness distribution keyed by
// hex-encoded Ed25519 public key; the sum of the map values equals WitnessFee.
// When no balance attesters contributed to the order, WitnessFees is nil and
// adapters fall back to paying the entire witness fee to the transaction
// witness (existing behaviour).
type FeeBreakdown struct {
	MaintainerFee      *big.Int            // fee to protocol maintainer (from PRC)
	ServiceProviderFee *big.Int            // fee to service provider (zero if no receipt)
	ArbitratorFee      *big.Int            // fee to arbitrator (zero if no dispute)
	WitnessFee         *big.Int            // aggregate fee to witnesses (zero if no attestations)
	WitnessFees        map[string]*big.Int // optional per-witness distribution, hex(pubkey) -> amount
	SellerProceeds     *big.Int            // remaining amount to seller
	Total              *big.Int            // total escrow amount
}

// TotalWitnessFee returns the aggregate witness fee. If WitnessFees is populated,
// it returns the sum of the per-witness amounts (and sanity-asserts against
// WitnessFee); otherwise it returns WitnessFee (or zero when nil).
func (f FeeBreakdown) TotalWitnessFee() *big.Int {
	if len(f.WitnessFees) > 0 {
		sum := new(big.Int)
		for _, v := range f.WitnessFees {
			if v != nil {
				sum.Add(sum, v)
			}
		}
		return sum
	}
	if f.WitnessFee == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(f.WitnessFee)
}

// FeeOptions configures the fee calculation inputs.
type FeeOptions struct {
	MaintainerBPS      uint32 // from PRC (immutable), max 500
	HasServiceProvider bool
	ServiceProviderBPS uint32 // max 200
	HasDispute         bool
	ArbitratorBPS      uint32 // max 300
	HasWitness         bool
	WitnessBPS         uint32 // max 100
}

// ReleaseParams contains parameters for releasing an escrow to the seller.
type ReleaseParams struct {
	ReceiptHash   []byte       // service receipt Merkle root (if applicable)
	WitnessHashes [][]byte     // attestation hashes from witness quorum
	Fees          FeeBreakdown // pre-calculated fee breakdown
}

// DisputeParams contains parameters for flagging an escrow as disputed.
type DisputeParams struct {
	Reason       string // human-readable dispute reason
	EvidenceHash []byte // hash of off-chain evidence bundle
	DisputerAddr string // address of the party raising the dispute
}

// Ruling represents an arbitrator's ruling on a disputed escrow.
type Ruling struct {
	BuyerPercent   uint32 // percentage of escrow to buyer (0-100)
	SellerPercent  uint32 // percentage of escrow to seller (0-100)
	ArbitratorAddr string
	Signature      []byte // arbitrator's signature on the ruling
	ReasonHash     []byte // hash of the reasoning document
}

// EscrowState represents the current on-chain state of an escrow.
type EscrowState struct {
	Address        string
	Buyer          string
	Seller         string
	Amount         *big.Int
	Currency       string
	Status         EscrowStatus
	ArbitratorAddr string
	CreatedAt      uint64 // block timestamp
	TimeoutAt      uint64 // block timestamp
	PRCAddress     string
}

// EscrowStatus represents the lifecycle state of an escrow.
type EscrowStatus int

const (
	EscrowStatusPending   EscrowStatus = iota // created, awaiting funding
	EscrowStatusFunded                        // buyer has funded
	EscrowStatusReleased                      // seller paid, escrow complete
	EscrowStatusDisputed                      // dispute flag raised
	EscrowStatusSettled                       // arbitrator ruled, funds distributed
	EscrowStatusRefunded                      // timeout reached, buyer refunded
	EscrowStatusCancelled                     // cancelled before funding
)

// UnsignedTx represents an unsigned transaction ready for signing.
type UnsignedTx struct {
	ChainID    string   // target chain
	To         string   // destination address (contract or recipient)
	Amount     *big.Int // value to transfer (may be zero for contract calls)
	Payload    []byte   // serialized transaction data (ABI-encoded for EVM, script for BTC)
	GasLimit   uint64   // estimated gas (EVM only)
	GasPrice   *big.Int // gas price or max fee (EVM only)
	Nonce      uint64   // sender nonce
	EscrowAddr string   // escrow contract address (for reference)
}

// AdapterInfo contains metadata about a loaded adapter.
type AdapterInfo struct {
	ChainID    string
	Currency   string
	Symbol     string
	Version    string
	PRCAddress string
	SignedBy   []byte // maintainer public key that signed this adapter
}

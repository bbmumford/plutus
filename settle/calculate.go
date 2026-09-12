package settle

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bbmumford/plutus/adapter"
)

// BPS constants and hard caps. Exported so adapters (e.g. wallet/signer_btc.go)
// can reference the canonical caps without re-declaring them.
const (
	BPSBase            = 10000
	MaintainerFeeBPSCap = 500  // 5%
	WitnessBPSCap      = 100  // 1%
	ServiceProvBPSCap  = 200  // 2%
	ArbitratorBPSCap   = 300  // 3%
	CombinedBPSCap     = 1000 // 10%

	// Unexported aliases for backwards-compat within this package.
	bpsBase           = BPSBase
	maxMaintainerBPS  = MaintainerFeeBPSCap
	maxWitnessBPS     = WitnessBPSCap
	maxServiceProvBPS = ServiceProvBPSCap
	maxArbitratorBPS  = ArbitratorBPSCap
	maxCombinedBPS    = CombinedBPSCap
)

// FeeCalculator performs deterministic fee calculations using big.Int BPS math.
// All division rounds down (truncation), and the seller receives the remainder
// after all fees, ensuring the total always equals the input amount exactly.
type FeeCalculator struct{}

// NewFeeCalculator returns a new FeeCalculator.
func NewFeeCalculator() *FeeCalculator {
	return &FeeCalculator{}
}

// Calculate computes the fee breakdown for a given amount and fee options.
// All arithmetic uses big.Int to avoid floating-point precision loss.
// The seller proceeds are computed as the remainder (total minus all fees),
// guaranteeing the sum of all components equals the total exactly.
//
// This is equivalent to CalculateWithWitnesses(amount, opts, nil): no balance
// attesters are credited, so the aggregate WitnessFee is payable to a single
// transaction-witness recipient at adapter settlement time.
func (c *FeeCalculator) Calculate(amount *big.Int, opts adapter.FeeOptions) (adapter.FeeBreakdown, error) {
	return c.CalculateWithWitnesses(amount, opts, nil)
}

// CalculateWithWitnesses is the explicit form that also attributes the
// witness fee across a set of hex-encoded witness pubkeys (typically sourced
// from BalanceVerifier.RecentBalanceAttesters). When balanceAttesters is
// empty the output matches Calculate exactly (WitnessFees left nil). The
// aggregate WitnessFee is always amount * WitnessBPS / 10000 regardless of
// how many witnesses split it.
func (c *FeeCalculator) CalculateWithWitnesses(amount *big.Int, opts adapter.FeeOptions, balanceAttesters []string) (adapter.FeeBreakdown, error) {
	if amount == nil || amount.Sign() <= 0 {
		return adapter.FeeBreakdown{}, errors.New("plutus/settle: amount must be positive")
	}

	// Validate hard caps.
	if opts.MaintainerBPS > maxMaintainerBPS {
		return adapter.FeeBreakdown{}, fmt.Errorf("plutus/settle: maintainer BPS %d exceeds cap %d", opts.MaintainerBPS, maxMaintainerBPS)
	}
	if opts.HasWitness && opts.WitnessBPS > maxWitnessBPS {
		return adapter.FeeBreakdown{}, fmt.Errorf("plutus/settle: witness BPS %d exceeds cap %d", opts.WitnessBPS, maxWitnessBPS)
	}
	if opts.HasServiceProvider && opts.ServiceProviderBPS > maxServiceProvBPS {
		return adapter.FeeBreakdown{}, fmt.Errorf("plutus/settle: service provider BPS %d exceeds cap %d", opts.ServiceProviderBPS, maxServiceProvBPS)
	}
	if opts.HasDispute && opts.ArbitratorBPS > maxArbitratorBPS {
		return adapter.FeeBreakdown{}, fmt.Errorf("plutus/settle: arbitrator BPS %d exceeds cap %d", opts.ArbitratorBPS, maxArbitratorBPS)
	}

	// Validate combined cap.
	combinedBPS := uint32(opts.MaintainerBPS)
	if opts.HasWitness {
		combinedBPS += opts.WitnessBPS
	}
	if opts.HasServiceProvider {
		combinedBPS += opts.ServiceProviderBPS
	}
	if opts.HasDispute {
		combinedBPS += opts.ArbitratorBPS
	}
	if combinedBPS > maxCombinedBPS {
		return adapter.FeeBreakdown{}, fmt.Errorf("plutus/settle: combined BPS %d exceeds cap %d", combinedBPS, maxCombinedBPS)
	}

	base := new(big.Int).Set(amount)
	bps := big.NewInt(bpsBase)

	// Calculate each fee: floor(amount * feeBPS / 10000).
	maintainerFee := bpsMul(base, opts.MaintainerBPS, bps)

	var witnessFee *big.Int
	if opts.HasWitness {
		witnessFee = bpsMul(base, opts.WitnessBPS, bps)
	} else {
		witnessFee = new(big.Int)
	}

	var serviceFee *big.Int
	if opts.HasServiceProvider {
		serviceFee = bpsMul(base, opts.ServiceProviderBPS, bps)
	} else {
		serviceFee = new(big.Int)
	}

	var arbitratorFee *big.Int
	if opts.HasDispute {
		arbitratorFee = bpsMul(base, opts.ArbitratorBPS, bps)
	} else {
		arbitratorFee = new(big.Int)
	}

	// Seller proceeds = total - all fees (remainder to avoid rounding errors).
	totalFees := new(big.Int)
	totalFees.Add(totalFees, maintainerFee)
	totalFees.Add(totalFees, witnessFee)
	totalFees.Add(totalFees, serviceFee)
	totalFees.Add(totalFees, arbitratorFee)

	sellerProceeds := new(big.Int).Sub(base, totalFees)
	if sellerProceeds.Sign() < 0 {
		return adapter.FeeBreakdown{}, errors.New("plutus/settle: fees exceed total amount")
	}

	fb := adapter.FeeBreakdown{
		MaintainerFee:      maintainerFee,
		ServiceProviderFee: serviceFee,
		ArbitratorFee:      arbitratorFee,
		WitnessFee:         witnessFee,
		SellerProceeds:     sellerProceeds,
		Total:              new(big.Int).Set(amount),
	}
	if len(balanceAttesters) > 0 && opts.HasWitness && witnessFee.Sign() > 0 {
		fb.WitnessFees = splitWitnessFeeEqual(witnessFee, balanceAttesters)
	}
	return fb, nil
}

// splitWitnessFeeEqual returns a distribution map over attesters that sums to
// witnessFee exactly. Equal shares with the remainder going to the first
// attester so the aggregate total is preserved (no dust lost to truncation).
// Duplicate pubkeys in attesters collapse to a single entry — the caller is
// expected to have already deduped via RecentBalanceAttesters, but we guard.
func splitWitnessFeeEqual(witnessFee *big.Int, attesters []string) map[string]*big.Int {
	seen := make(map[string]struct{}, len(attesters))
	uniq := make([]string, 0, len(attesters))
	for _, k := range attesters {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		uniq = append(uniq, k)
	}
	if len(uniq) == 0 {
		return nil
	}
	n := big.NewInt(int64(len(uniq)))
	share := new(big.Int).Quo(witnessFee, n)
	remainder := new(big.Int).Sub(witnessFee, new(big.Int).Mul(share, n))
	out := make(map[string]*big.Int, len(uniq))
	for i, k := range uniq {
		amt := new(big.Int).Set(share)
		if i == 0 {
			amt.Add(amt, remainder)
		}
		out[k] = amt
	}
	return out
}

// Verify checks that a transaction's fee amounts match the expected breakdown.
func (c *FeeCalculator) Verify(tx *adapter.UnsignedTx, expected adapter.FeeBreakdown) error {
	if tx == nil {
		return errors.New("plutus/settle: transaction is nil")
	}
	if expected.Total == nil || expected.Total.Sign() <= 0 {
		return errors.New("plutus/settle: expected total must be positive")
	}

	// Verify component sum.
	sum := new(big.Int)
	sum.Add(sum, expected.MaintainerFee)
	if expected.ServiceProviderFee != nil {
		sum.Add(sum, expected.ServiceProviderFee)
	}
	if expected.ArbitratorFee != nil {
		sum.Add(sum, expected.ArbitratorFee)
	}
	if expected.WitnessFee != nil {
		sum.Add(sum, expected.WitnessFee)
	}
	sum.Add(sum, expected.SellerProceeds)

	if sum.Cmp(expected.Total) != 0 {
		return fmt.Errorf("plutus/settle: fee components sum to %s but total is %s", sum, expected.Total)
	}

	// Cross-check against TX amount if present.
	if tx.Amount != nil && tx.Amount.Cmp(expected.Total) != 0 {
		return fmt.Errorf("plutus/settle: tx amount %s does not match expected total %s", tx.Amount, expected.Total)
	}

	return nil
}

// bpsMul computes floor(amount * bpsVal / bpsBase) using big.Int.
func bpsMul(amount *big.Int, bpsVal uint32, bpsBase *big.Int) *big.Int {
	if bpsVal == 0 {
		return new(big.Int)
	}
	result := new(big.Int).Mul(amount, big.NewInt(int64(bpsVal)))
	result.Div(result, bpsBase)
	return result
}

package btc

import (
	"math/big"
	"testing"

	"github.com/bbmumford/plutus/adapter"
)

func newFeeTestAdapter(t *testing.T) *BTCAdapter {
	t.Helper()
	a, err := NewBTCAdapter(BTCAdapterConfig{
		Transport:      &nopTransport{},
		Network:        "mainnet",
		MaintainerAddr: testMaintainerAddr,
	})
	if err != nil {
		t.Fatalf("NewBTCAdapter: %v", err)
	}
	return a
}

// The adapter's breakdown is settlement's: each part floors amount*bps/10000
// and the seller takes the remainder, so the parts sum to the amount.
func TestBTCCalculateFeesSumsToTheAmount(t *testing.T) {
	a := newFeeTestAdapter(t)
	amount := big.NewInt(1_000_003)
	fees, err := a.CalculateFees(amount, adapter.FeeOptions{
		MaintainerBPS: 100, HasWitness: true, WitnessBPS: 25,
		HasServiceProvider: true, ServiceProviderBPS: 50, HasDispute: true, ArbitratorBPS: 150,
	})
	if err != nil {
		t.Fatalf("CalculateFees: %v", err)
	}
	if fees.MaintainerFee.Int64() != 10_000 || fees.WitnessFee.Int64() != 2_500 ||
		fees.ServiceProviderFee.Int64() != 5_000 || fees.ArbitratorFee.Int64() != 15_000 {
		t.Fatalf("parts: %+v", fees)
	}
	sum := new(big.Int).Add(fees.MaintainerFee, fees.WitnessFee)
	sum.Add(sum, fees.ServiceProviderFee).Add(sum, fees.ArbitratorFee).Add(sum, fees.SellerProceeds)
	if sum.Cmp(amount) != 0 || fees.Total.Cmp(amount) != 0 {
		t.Fatalf("parts sum to %s and total is %s, want both %s", sum, fees.Total, amount)
	}
}

// Fee options past a role's cap, or past the combined cap, are refused, so the
// adapter never reports a breakdown whose fees outrun the amount.
func TestBTCCalculateFeesRefusesOptionsPastTheCaps(t *testing.T) {
	a := newFeeTestAdapter(t)
	for name, opts := range map[string]adapter.FeeOptions{
		"maintainer over 500":  {MaintainerBPS: 501},
		"witness over 100":     {HasWitness: true, WitnessBPS: 101},
		"service over 200":     {HasServiceProvider: true, ServiceProviderBPS: 201},
		"arbitrator over 300":  {HasDispute: true, ArbitratorBPS: 301},
		"combined over 1000":   {MaintainerBPS: 500, HasWitness: true, WitnessBPS: 100, HasServiceProvider: true, ServiceProviderBPS: 200, HasDispute: true, ArbitratorBPS: 300},
		"more than the amount": {MaintainerBPS: 20000},
	} {
		if fees, err := a.CalculateFees(big.NewInt(1_000_000), opts); err == nil {
			t.Errorf("%s: answered %+v, want a refusal", name, fees)
		}
	}
	if _, err := a.CalculateFees(big.NewInt(0), adapter.FeeOptions{MaintainerBPS: 100}); err == nil {
		t.Error("a zero amount was answered, want a refusal")
	}
}

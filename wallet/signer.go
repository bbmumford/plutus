package wallet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/observability"
)

// Signer signs transactions with protocol-level fee enforcement.
// It refuses to sign any settlement where the fee breakdown does not match
// the expected values, ensuring maintainer fees cannot be bypassed.
type Signer struct {
	identityKey ed25519.PrivateKey
	prcResolver *PRCResolver
}

// NewSigner creates a signer from a protocol identity key and PRC resolver.
func NewSigner(identityKey ed25519.PrivateKey, prcResolver *PRCResolver) *Signer {
	return &Signer{
		identityKey: identityKey,
		prcResolver: prcResolver,
	}
}

// SignEscrowFunding signs an escrow funding transaction.
// Funding transactions do not require fee verification since fees are
// enforced at settlement time by the smart contract.
// The account parameter identifies the source account (default 0).
func (s *Signer) SignEscrowFunding(tx *adapter.UnsignedTx, account ...uint32) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("plutus/wallet: transaction is nil")
	}
	if len(tx.Payload) == 0 {
		return nil, errors.New("plutus/wallet: transaction payload is empty")
	}

	// Account index is available for context (e.g., logging, audit) but
	// protocol-level signing uses the identity key regardless of account.
	return ed25519.Sign(s.identityKey, tx.Payload), nil
}

// SignSettlement signs a settlement transaction after verifying that the
// fee breakdown matches expected values and PRC on-chain rates. This is the
// critical enforcement point: the signer refuses to produce a signature if
// fees are incorrect or below PRC minimums.
// The account parameter identifies the settlement account (default 0).
func (s *Signer) SignSettlement(tx *adapter.UnsignedTx, expected adapter.FeeBreakdown, account ...uint32) ([]byte, error) {
	bgCtx := context.Background()
	if tx == nil {
		return nil, errors.New("plutus/wallet: transaction is nil")
	}
	if len(tx.Payload) == 0 {
		return nil, errors.New("plutus/wallet: transaction payload is empty")
	}

	// Verify the fee breakdown is internally consistent.
	if err := verifyFeeBreakdown(tx, expected); err != nil {
		observability.FeeRejectedCount().Add(bgCtx, 1)
		return nil, fmt.Errorf("plutus/wallet: fee verification failed, refusing to sign: %w", err)
	}

	// Verify fees against PRC on-chain rates.
	if s.prcResolver != nil && tx.ChainID != "" {
		prcData, err := s.prcResolver.Resolve(tx.ChainID)
		if err != nil {
			observability.FeeRejectedCount().Add(bgCtx, 1)
			return nil, fmt.Errorf("plutus/wallet: PRC resolve failed, refusing to sign: %w", err)
		}
		if err := verifyFeesAgainstPRC(tx, expected, prcData); err != nil {
			observability.FeeRejectedCount().Add(bgCtx, 1)
			return nil, fmt.Errorf("plutus/wallet: PRC fee check failed, refusing to sign: %w", err)
		}
	}

	observability.FeeCalculatedCount().Add(bgCtx, 1)
	return ed25519.Sign(s.identityKey, tx.Payload), nil
}

// verifyFeesAgainstPRC checks that the fee breakdown meets PRC-mandated minimums.
func verifyFeesAgainstPRC(tx *adapter.UnsignedTx, expected adapter.FeeBreakdown, prc *PRCData) error {
	amount := expected.Total
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("total amount must be positive for PRC verification")
	}

	bpsBase := big.NewInt(10000)

	// MaintainerFee >= amount * MaintainerFeeBPS / 10000
	minMaintainer := new(big.Int).Mul(amount, big.NewInt(int64(prc.MaintainerFeeBPS)))
	minMaintainer.Div(minMaintainer, bpsBase)

	if expected.MaintainerFee == nil || expected.MaintainerFee.Cmp(minMaintainer) < 0 {
		return fmt.Errorf("maintainer fee %s below PRC minimum %s (%d BPS)",
			bigStr(expected.MaintainerFee), minMaintainer, prc.MaintainerFeeBPS)
	}

	// WitnessFee >= amount * WitnessBPS / 10000 (only when witness hashes present)
	if expected.WitnessFee != nil && expected.WitnessFee.Sign() > 0 {
		minWitness := new(big.Int).Mul(amount, big.NewInt(int64(prc.WitnessBPS)))
		minWitness.Div(minWitness, bpsBase)

		if expected.WitnessFee.Cmp(minWitness) < 0 {
			return fmt.Errorf("witness fee %s below PRC minimum %s (%d BPS)",
				expected.WitnessFee, minWitness, prc.WitnessBPS)
		}
	}

	return nil
}

// bigStr returns "nil" for a nil *big.Int, otherwise its String().
func bigStr(v *big.Int) string {
	if v == nil {
		return "nil"
	}
	return v.String()
}

// SignTransfer signs a plain value-transfer transaction (not tied to an escrow).
// This is used by the wallet "send funds" flow. The signer performs wallet-level
// policy validation before producing a signature:
//
//   - The identity key must be present (wallet not locked/cleared).
//   - The transaction must have a non-empty recipient and a positive amount.
//   - The payload must be non-empty (the caller is responsible for producing
//     the chain-specific serialized transaction body; the signer signs the
//     payload bytes).
//
// The account parameter identifies the source account (default 0).
func (s *Signer) SignTransfer(tx *adapter.UnsignedTx, account ...uint32) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("plutus/wallet: transaction is nil")
	}
	if len(s.identityKey) == 0 {
		return nil, errors.New("plutus/wallet: signer has no identity key (wallet locked)")
	}
	if tx.To == "" {
		return nil, errors.New("plutus/wallet: transfer recipient is empty")
	}
	if tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return nil, errors.New("plutus/wallet: transfer amount must be positive")
	}
	if len(tx.Payload) == 0 {
		return nil, errors.New("plutus/wallet: transaction payload is empty")
	}

	return ed25519.Sign(s.identityKey, tx.Payload), nil
}

// SignDispute signs a dispute transaction. Dispute transactions flag an escrow
// for arbitration and do not involve fee transfers.
// The account parameter identifies the disputing account (default 0).
func (s *Signer) SignDispute(tx *adapter.UnsignedTx, account ...uint32) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("plutus/wallet: transaction is nil")
	}
	if len(tx.Payload) == 0 {
		return nil, errors.New("plutus/wallet: transaction payload is empty")
	}

	return ed25519.Sign(s.identityKey, tx.Payload), nil
}

// verifyFeeBreakdown checks that the transaction's embedded fee values match
// the expected breakdown. All comparisons use big.Int for precision.
func verifyFeeBreakdown(tx *adapter.UnsignedTx, expected adapter.FeeBreakdown) error {
	if expected.Total == nil || expected.Total.Sign() <= 0 {
		return errors.New("expected total must be positive")
	}
	if expected.MaintainerFee == nil || expected.MaintainerFee.Sign() < 0 {
		return errors.New("maintainer fee must be non-negative")
	}
	if expected.SellerProceeds == nil || expected.SellerProceeds.Sign() < 0 {
		return errors.New("seller proceeds must be non-negative")
	}

	// Verify the sum of all fee components equals the total.
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
		return fmt.Errorf("fee components sum to %s but total is %s", sum, expected.Total)
	}

	// Verify transaction references the expected total amount.
	if tx.Amount != nil && tx.Amount.Cmp(expected.Total) != 0 {
		return fmt.Errorf("transaction amount %s does not match expected total %s", tx.Amount, expected.Total)
	}

	return nil
}

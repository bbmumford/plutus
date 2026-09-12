/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package btc

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// UTXOSelector selects unspent outputs to fund a transaction.
// Uses largest-first selection to minimize the number of inputs,
// which reduces transaction size and fees.
type UTXOSelector struct {
	// DustThreshold is the minimum output value in satoshis. Outputs below
	// this are not considered as change outputs. Default: 546 sat.
	DustThreshold *big.Int
}

// NewUTXOSelector creates a new UTXO selector with default settings.
func NewUTXOSelector() *UTXOSelector {
	return &UTXOSelector{
		DustThreshold: big.NewInt(546), // Bitcoin dust limit
	}
}

// Selection contains the result of UTXO selection.
type Selection struct {
	// Selected UTXOs to use as inputs.
	Inputs []UTXO
	// Total value of selected inputs in satoshis.
	TotalInput *big.Int
	// Target amount to send in satoshis.
	Target *big.Int
	// Estimated fee in satoshis.
	Fee *big.Int
	// Change amount (TotalInput - Target - Fee). Zero if no change.
	Change *big.Int
	// Whether a change output is needed.
	HasChange bool
}

// Select chooses UTXOs to fund a transaction for the given target amount.
// Uses largest-first selection: sorts UTXOs by value descending, then
// selects until the target + fee is met.
//
// Parameters:
//   - utxos: available unspent outputs
//   - target: amount to send in satoshis
//   - feePerVByte: fee rate in satoshis per virtual byte
//   - extraOutputSize: additional output size beyond the payment output
//     (e.g., for OP_RETURN or multisig)
func (s *UTXOSelector) Select(utxos []UTXO, target *big.Int, feePerVByte float64, extraOutputSize int) (*Selection, error) {
	if target == nil || target.Sign() <= 0 {
		return nil, errors.New("btc/utxo: target must be positive")
	}
	if feePerVByte <= 0 {
		return nil, errors.New("btc/utxo: fee rate must be positive")
	}
	if len(utxos) == 0 {
		return nil, errors.New("btc/utxo: no UTXOs available")
	}

	// Sort by value descending (largest first).
	sorted := make([]UTXO, len(utxos))
	copy(sorted, utxos)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value.Cmp(sorted[j].Value) > 0
	})

	selected := make([]UTXO, 0)
	totalInput := new(big.Int)

	for _, utxo := range sorted {
		selected = append(selected, utxo)
		totalInput.Add(totalInput, utxo.Value)

		// Estimate fee with current input count.
		fee := s.estimateFee(len(selected), 2, feePerVByte, extraOutputSize) // 2 outputs: payment + change
		required := new(big.Int).Add(target, fee)

		if totalInput.Cmp(required) >= 0 {
			// We have enough. Calculate change.
			change := new(big.Int).Sub(totalInput, required)
			hasChange := change.Cmp(s.DustThreshold) > 0

			if !hasChange {
				// Change is dust — donate to fees instead.
				// Recalculate fee with only 1 output (no change).
				fee = s.estimateFee(len(selected), 1, feePerVByte, extraOutputSize)
				change = new(big.Int).Sub(totalInput, new(big.Int).Add(target, fee))
				if change.Sign() < 0 {
					// Still not enough without the change output — continue selecting.
					continue
				}
				// The remaining is absorbed into the fee.
				fee.Add(fee, change)
				change = new(big.Int)
			}

			return &Selection{
				Inputs:     selected,
				TotalInput: totalInput,
				Target:     new(big.Int).Set(target),
				Fee:        fee,
				Change:     change,
				HasChange:  hasChange,
			}, nil
		}
	}

	return nil, fmt.Errorf("btc/utxo: insufficient funds: have %s sat, need %s sat + fees", totalInput, target)
}

// estimateFee estimates the transaction fee based on input/output counts.
// Uses segwit (P2WSH) input size estimation.
//
// SegWit transaction structure (approximate vsize):
//   - Overhead: 10.5 vbytes (version + locktime + segwit marker)
//   - P2WSH input: ~41 vbytes (for witness discount)
//   - P2WPKH output: 31 vbytes
//   - P2WSH output: 43 vbytes
func (s *UTXOSelector) estimateFee(numInputs, numOutputs int, feePerVByte float64, extraOutputSize int) *big.Int {
	const (
		txOverhead   = 11  // version(4) + locktime(4) + segwit marker(~2) + input/output count(1)
		p2wshInput   = 41  // outpoint(36) + sequence(4) + witness estimate with discount
		p2wpkhOutput = 31  // value(8) + scriptPubKey length(1) + P2WPKH script(22)
		p2wshOutput  = 43  // value(8) + scriptPubKey length(1) + P2WSH script(34)
	)

	vsize := txOverhead +
		numInputs*p2wshInput +
		numOutputs*p2wpkhOutput +
		extraOutputSize

	feeSat := int64(float64(vsize) * feePerVByte)
	if feeSat < 1 {
		feeSat = 1
	}

	return big.NewInt(feeSat)
}

// TotalUTXOValue sums the values of a UTXO set.
func TotalUTXOValue(utxos []UTXO) *big.Int {
	total := new(big.Int)
	for _, u := range utxos {
		total.Add(total, u.Value)
	}
	return total
}

// FilterConfirmed returns only UTXOs with at least minConf confirmations.
func FilterConfirmed(utxos []UTXO, minConf uint32) []UTXO {
	result := make([]UTXO, 0, len(utxos))
	for _, u := range utxos {
		if u.Confirmations >= minConf {
			result = append(result, u)
		}
	}
	return result
}

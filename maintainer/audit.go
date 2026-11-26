/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package maintainer

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// WitnessQueryService is the interface for querying witness attestation records.
// Implemented by the witness/ledger layer.
type WitnessQueryService interface {
	// QuerySettlementEvents returns settlement attestations for the given chain
	// and time range.
	QuerySettlementEvents(ctx context.Context, chainID string, from, to time.Time) ([]SettlementEvent, error)

	// QueryEscrowSettlement returns the settlement details for a specific escrow.
	QueryEscrowSettlement(ctx context.Context, chainID string, escrowAddr string) (*SettlementEvent, error)
}

// SettlementEvent represents a witness-attested settlement.
type SettlementEvent struct {
	ChainID        string    `json:"chainID"`
	EscrowAddr     string    `json:"escrowAddr"`
	TxHash         string    `json:"txHash"`
	BlockNumber    uint64    `json:"blockNumber"`
	Amount         *big.Int  `json:"amount"`
	MaintainerFee  *big.Int  `json:"maintainerFee"`
	WitnessFee     *big.Int  `json:"witnessFee"`
	SellerProceeds *big.Int  `json:"sellerProceeds"`
	Buyer          string    `json:"buyer"`
	Seller         string    `json:"seller"`
	Arbitrator     string    `json:"arbitrator,omitempty"`
	Disputed       bool      `json:"disputed"`
	AttestedAt     time.Time `json:"attestedAt"`
	WitnessCount   int       `json:"witnessCount"`
	Quorum         bool      `json:"quorum"`
}

// AuditReport is the result of a fee collection audit.
type AuditReport struct {
	// ChainID is the chain that was audited.
	ChainID string `json:"chainID"`
	// Period is the audit time range.
	PeriodFrom time.Time `json:"periodFrom"`
	PeriodTo   time.Time `json:"periodTo"`

	// Settlement statistics.
	TotalSettlements int `json:"totalSettlements"`
	DisputedCount    int `json:"disputedCount"`
	QuorumVerified   int `json:"quorumVerified"`

	// Fee totals.
	TotalVolume         *big.Int `json:"totalVolume"`
	TotalMaintainerFees *big.Int `json:"totalMaintainerFees"`
	TotalWitnessFees    *big.Int `json:"totalWitnessFees"`
	TotalSellerProceeds *big.Int `json:"totalSellerProceeds"`

	// Fee accuracy metrics.
	ExpectedMaintainerBPS uint32 `json:"expectedMaintainerBPS"`
	ActualMaintainerBPS   uint32 `json:"actualMaintainerBPS"` // computed from totals
	FeeAccurate           bool   `json:"feeAccurate"`

	// Individual settlements (sorted by time).
	Settlements []SettlementEvent `json:"settlements"`

	// Anomalies detected.
	Anomalies []AuditAnomaly `json:"anomalies,omitempty"`

	// Generation metadata.
	GeneratedAt time.Time `json:"generatedAt"`
}

// AuditAnomaly flags a settlement that doesn't match expected fee parameters.
type AuditAnomaly struct {
	EscrowAddr  string `json:"escrowAddr"`
	TxHash      string `json:"txHash"`
	Type        string `json:"type"` // "fee_mismatch", "no_quorum", "missing_witness_fee"
	Description string `json:"description"`
}

// Auditor performs fee collection audits by querying witness attestation records.
type Auditor struct {
	witnessService WitnessQueryService
}

// NewAuditor creates a new fee collection auditor.
func NewAuditor(witnessService WitnessQueryService) (*Auditor, error) {
	if witnessService == nil {
		return nil, fmt.Errorf("maintainer/audit: witness query service is nil")
	}
	return &Auditor{witnessService: witnessService}, nil
}

// Audit performs a fee collection audit for the given chain and time period.
// It queries all settlement events via witness attestations and verifies that
// maintainer fees were correctly extracted.
func (a *Auditor) Audit(ctx context.Context, chainID string, from, to time.Time, expectedMaintainerBPS uint32) (*AuditReport, error) {
	if chainID == "" {
		return nil, fmt.Errorf("maintainer/audit: chainID is empty")
	}
	if from.After(to) {
		return nil, fmt.Errorf("maintainer/audit: from (%s) is after to (%s)", from, to)
	}

	// Query all settlement events in the period.
	events, err := a.witnessService.QuerySettlementEvents(ctx, chainID, from, to)
	if err != nil {
		return nil, fmt.Errorf("maintainer/audit: query settlements: %w", err)
	}

	// Sort by attestation time.
	sort.Slice(events, func(i, j int) bool {
		return events[i].AttestedAt.Before(events[j].AttestedAt)
	})

	// Aggregate.
	report := &AuditReport{
		ChainID:               chainID,
		PeriodFrom:            from,
		PeriodTo:              to,
		TotalSettlements:      len(events),
		TotalVolume:           new(big.Int),
		TotalMaintainerFees:   new(big.Int),
		TotalWitnessFees:      new(big.Int),
		TotalSellerProceeds:   new(big.Int),
		ExpectedMaintainerBPS: expectedMaintainerBPS,
		Settlements:           events,
		GeneratedAt:           time.Now().UTC(),
	}

	bpsBase := big.NewInt(10000)

	for _, ev := range events {
		if ev.Amount != nil {
			report.TotalVolume.Add(report.TotalVolume, ev.Amount)
		}
		if ev.MaintainerFee != nil {
			report.TotalMaintainerFees.Add(report.TotalMaintainerFees, ev.MaintainerFee)
		}
		if ev.WitnessFee != nil {
			report.TotalWitnessFees.Add(report.TotalWitnessFees, ev.WitnessFee)
		}
		if ev.SellerProceeds != nil {
			report.TotalSellerProceeds.Add(report.TotalSellerProceeds, ev.SellerProceeds)
		}

		if ev.Disputed {
			report.DisputedCount++
		}
		if ev.Quorum {
			report.QuorumVerified++
		}

		// Check for anomalies.
		anomalies := a.checkSettlement(ev, expectedMaintainerBPS)
		report.Anomalies = append(report.Anomalies, anomalies...)
	}

	// Compute actual BPS from totals.
	if report.TotalVolume.Sign() > 0 {
		// actualBPS = (totalMaintainerFees * 10000) / totalVolume
		actualBPS := new(big.Int).Mul(report.TotalMaintainerFees, bpsBase)
		actualBPS.Div(actualBPS, report.TotalVolume)
		report.ActualMaintainerBPS = uint32(actualBPS.Uint64())

		// Fee is "accurate" if within 1 BPS of expected (rounding tolerance).
		diff := int64(report.ActualMaintainerBPS) - int64(expectedMaintainerBPS)
		if diff < 0 {
			diff = -diff
		}
		report.FeeAccurate = diff <= 1
	}

	return report, nil
}

// AuditEscrow performs a fee audit on a single escrow settlement.
func (a *Auditor) AuditEscrow(ctx context.Context, chainID string, escrowAddr string, expectedMaintainerBPS uint32) (*AuditReport, error) {
	if chainID == "" || escrowAddr == "" {
		return nil, fmt.Errorf("maintainer/audit: chainID and escrowAddr are required")
	}

	event, err := a.witnessService.QueryEscrowSettlement(ctx, chainID, escrowAddr)
	if err != nil {
		return nil, fmt.Errorf("maintainer/audit: query escrow settlement: %w", err)
	}
	if event == nil {
		return nil, fmt.Errorf("maintainer/audit: no settlement found for escrow %s on %s", escrowAddr, chainID)
	}

	report := &AuditReport{
		ChainID:               chainID,
		PeriodFrom:            event.AttestedAt,
		PeriodTo:              event.AttestedAt,
		TotalSettlements:      1,
		TotalVolume:           new(big.Int).Set(event.Amount),
		TotalMaintainerFees:   new(big.Int).Set(event.MaintainerFee),
		TotalWitnessFees:      new(big.Int).Set(event.WitnessFee),
		TotalSellerProceeds:   new(big.Int).Set(event.SellerProceeds),
		ExpectedMaintainerBPS: expectedMaintainerBPS,
		Settlements:           []SettlementEvent{*event},
		GeneratedAt:           time.Now().UTC(),
	}

	if event.Disputed {
		report.DisputedCount = 1
	}
	if event.Quorum {
		report.QuorumVerified = 1
	}

	anomalies := a.checkSettlement(*event, expectedMaintainerBPS)
	report.Anomalies = anomalies

	// Compute actual BPS.
	if event.Amount.Sign() > 0 {
		actualBPS := new(big.Int).Mul(event.MaintainerFee, big.NewInt(10000))
		actualBPS.Div(actualBPS, event.Amount)
		report.ActualMaintainerBPS = uint32(actualBPS.Uint64())

		diff := int64(report.ActualMaintainerBPS) - int64(expectedMaintainerBPS)
		if diff < 0 {
			diff = -diff
		}
		report.FeeAccurate = diff <= 1
	}

	return report, nil
}

// checkSettlement validates a single settlement event for anomalies.
func (a *Auditor) checkSettlement(ev SettlementEvent, expectedBPS uint32) []AuditAnomaly {
	var anomalies []AuditAnomaly

	// Check quorum.
	if !ev.Quorum {
		anomalies = append(anomalies, AuditAnomaly{
			EscrowAddr:  ev.EscrowAddr,
			TxHash:      ev.TxHash,
			Type:        "no_quorum",
			Description: fmt.Sprintf("settlement attested by %d witnesses without quorum", ev.WitnessCount),
		})
	}

	// Check maintainer fee matches expected BPS.
	if ev.Amount != nil && ev.Amount.Sign() > 0 && ev.MaintainerFee != nil {
		expectedFee := new(big.Int).Mul(ev.Amount, big.NewInt(int64(expectedBPS)))
		expectedFee.Div(expectedFee, big.NewInt(10000))

		// Allow rounding tolerance of 1 token unit.
		diff := new(big.Int).Sub(ev.MaintainerFee, expectedFee)
		diff.Abs(diff)
		if diff.Cmp(big.NewInt(1)) > 0 {
			anomalies = append(anomalies, AuditAnomaly{
				EscrowAddr: ev.EscrowAddr,
				TxHash:     ev.TxHash,
				Type:       "fee_mismatch",
				Description: fmt.Sprintf(
					"maintainer fee %s does not match expected %s (at %d BPS)",
					ev.MaintainerFee, expectedFee, expectedBPS,
				),
			})
		}
	}

	// Check fee components sum.
	if ev.Amount != nil && ev.MaintainerFee != nil && ev.WitnessFee != nil && ev.SellerProceeds != nil {
		sum := new(big.Int)
		sum.Add(sum, ev.MaintainerFee)
		sum.Add(sum, ev.WitnessFee)
		sum.Add(sum, ev.SellerProceeds)

		if sum.Cmp(ev.Amount) != 0 {
			anomalies = append(anomalies, AuditAnomaly{
				EscrowAddr: ev.EscrowAddr,
				TxHash:     ev.TxHash,
				Type:       "fee_mismatch",
				Description: fmt.Sprintf(
					"fee components sum to %s but escrow amount is %s",
					sum, ev.Amount,
				),
			})
		}
	}

	return anomalies
}

// ReportSummary returns a human-readable summary of an audit report.
func ReportSummary(r *AuditReport) string {
	return fmt.Sprintf(
		"Audit Report: %s (%s to %s)\n"+
			"  Settlements: %d (disputed: %d, quorum-verified: %d)\n"+
			"  Total Volume: %s\n"+
			"  Maintainer Fees: %s (expected: %d BPS, actual: %d BPS, accurate: %v)\n"+
			"  Witness Fees: %s\n"+
			"  Seller Proceeds: %s\n"+
			"  Anomalies: %d",
		r.ChainID, r.PeriodFrom.Format("2006-01-02"), r.PeriodTo.Format("2006-01-02"),
		r.TotalSettlements, r.DisputedCount, r.QuorumVerified,
		r.TotalVolume,
		r.TotalMaintainerFees, r.ExpectedMaintainerBPS, r.ActualMaintainerBPS, r.FeeAccurate,
		r.TotalWitnessFees,
		r.TotalSellerProceeds,
		len(r.Anomalies),
	)
}

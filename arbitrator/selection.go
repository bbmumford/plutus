/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package arbitrator

// ReputationScorer provides reputation data for arbitrator ranking.
// Implemented by the reputation.ReputationService.
type ReputationScorer interface {
	// PositiveRate returns the positive trade completion rate for a pubkey (0.0 - 1.0).
	PositiveRate(pubkey []byte) float64
	// TotalTrades returns the number of trades for a pubkey.
	TotalTrades(pubkey []byte) int
}

// SelectionCriteria configures how FindBest ranks arbitrators.
type SelectionCriteria struct {
	Category string // required expertise category
	ChainID  string // required chain support
	MaxFee   uint32 // maximum acceptable fee in BPS (0 = no limit)
	Limit    int    // max results to return (0 = all matching)
}

// ScoredArbitrator pairs an ArbitratorProfile with its computed ranking score.
type ScoredArbitrator struct {
	Profile ArbitratorProfile
	Score   float64
}

// FindBest returns the top arbitrators for the given criteria, sorted by a
// composite score of reputation, fee competitiveness, and availability.
// The scoring formula weights:
//   - Reputation (positive rate * 0.5)
//   - Experience (logarithmic trade count * 0.3)
//   - Fee competitiveness (inverse fee ratio * 0.2)
func FindBest(registry *ArbitratorRegistry, scorer ReputationScorer, criteria SelectionCriteria) []ScoredArbitrator {
	candidates := registry.Find(criteria.Category, criteria.ChainID)

	if len(candidates) == 0 {
		return nil
	}

	// Filter by max fee
	var filtered []ArbitratorProfile
	for _, c := range candidates {
		if criteria.MaxFee > 0 && c.FeeBPS > criteria.MaxFee {
			continue
		}
		filtered = append(filtered, c)
	}

	if len(filtered) == 0 {
		return nil
	}

	// Score each candidate
	scored := make([]ScoredArbitrator, len(filtered))
	for i, prof := range filtered {
		score := computeScore(prof, scorer)
		scored[i] = ScoredArbitrator{
			Profile: prof,
			Score:   score,
		}
	}

	// Sort by score descending (insertion sort, registries are small)
	for i := 1; i < len(scored); i++ {
		for j := i; j > 0 && scored[j].Score > scored[j-1].Score; j-- {
			scored[j], scored[j-1] = scored[j-1], scored[j]
		}
	}

	// Apply limit
	if criteria.Limit > 0 && len(scored) > criteria.Limit {
		scored = scored[:criteria.Limit]
	}

	return scored
}

// computeScore calculates a composite ranking score for an arbitrator.
// Score range: 0.0 - 1.0 (higher is better).
func computeScore(prof ArbitratorProfile, scorer ReputationScorer) float64 {
	const (
		weightReputation = 0.5
		weightExperience = 0.3
		weightFee        = 0.2
	)

	// Reputation: positive trade completion rate (0.0 - 1.0)
	reputationScore := 0.5 // default for new arbitrators
	if scorer != nil {
		rate := scorer.PositiveRate(prof.PubKey)
		trades := scorer.TotalTrades(prof.PubKey)
		if trades > 0 {
			reputationScore = rate
		}
	}

	// Experience: logarithmic scaling of trade count
	// log2(trades+1) / log2(1001) normalizes to roughly 0-1 for 0-1000 trades
	experienceScore := 0.0
	if scorer != nil {
		trades := scorer.TotalTrades(prof.PubKey)
		if trades > 0 {
			experienceScore = log2Approx(float64(trades)+1) / log2Approx(1001)
			if experienceScore > 1.0 {
				experienceScore = 1.0
			}
		}
	}

	// Fee competitiveness: lower fee = higher score
	// Score = 1 - (feeBPS / maxFeeBPS)
	feeScore := 1.0
	if prof.FeeBPS > 0 {
		feeScore = 1.0 - float64(prof.FeeBPS)/float64(maxFeeBPS)
		if feeScore < 0 {
			feeScore = 0
		}
	}

	return (reputationScore * weightReputation) +
		(experienceScore * weightExperience) +
		(feeScore * weightFee)
}

// log2Approx computes an approximate log base 2 using repeated halving.
// This avoids importing math for a simple ranking function.
func log2Approx(x float64) float64 {
	if x <= 0 {
		return 0
	}
	result := 0.0
	for x >= 2.0 {
		x /= 2.0
		result++
	}
	// Linear interpolation for the fractional part
	if x > 1.0 {
		result += x - 1.0
	}
	return result
}

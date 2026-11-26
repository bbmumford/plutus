package witness

import (
	"math/big"
	"testing"
)

// An attester named twice is one recipient, and the shares still sum to the
// whole witness fee.
func TestSplitWitnessFeeCountsARepeatedAttesterOnce(t *testing.T) {
	split := SplitWitnessFee(big.NewInt(100), []string{"a", "a", "b"})
	if len(split) != 2 {
		t.Fatalf("got %d recipients, want 2: %v", len(split), split)
	}
	sum := new(big.Int)
	for _, v := range split {
		sum.Add(sum, v)
	}
	if sum.Int64() != 100 {
		t.Fatalf("shares sum to %s, want the whole fee 100: %v", sum, split)
	}
	if split["a"].Int64() != 50 || split["b"].Int64() != 50 {
		t.Fatalf("got a=%s b=%s, want 50 each", split["a"], split["b"])
	}
	one := SplitWitnessFee(big.NewInt(7), []string{"c", "c", "c"})
	if len(one) != 1 || one["c"].Int64() != 7 {
		t.Fatalf("one attester named three times: got %v, want c=7", one)
	}
}

// Every node splits the same fee among the same attesters identically, whatever
// order RecentBalanceAttesters returned them in: the remainder goes to the
// attester whose name sorts first.
func TestSplitWitnessFeeIsTheSameInEveryOrder(t *testing.T) {
	want := map[string]int64{"a": 4, "b": 3, "c": 3}
	for _, order := range [][]string{{"a", "b", "c"}, {"b", "c", "a"}, {"c", "a", "b"}, {"c", "b", "a"}} {
		got := SplitWitnessFee(big.NewInt(10), order)
		if len(got) != len(want) {
			t.Fatalf("order %v: %d recipients, want %d", order, len(got), len(want))
		}
		for k, v := range want {
			if got[k] == nil || got[k].Int64() != v {
				t.Errorf("order %v: %s gets %v, want %d", order, k, got[k], v)
			}
		}
	}
}

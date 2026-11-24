package btc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// cannedTransport answers every RPC with one fixed result, so a test can hand
// ListUnspent exactly the JSON a node would send.
type cannedTransport struct{ result string }

func (c cannedTransport) SendRPC(context.Context, string, string, []byte) (json.RawMessage, error) {
	return json.RawMessage(c.result), nil
}

func listUnspentOf(t *testing.T, amounts ...string) ([]UTXO, error) {
	t.Helper()
	outs := make([]string, len(amounts))
	for i, a := range amounts {
		outs[i] = `{"txid":"aa","vout":` + string(rune('0'+i)) + `,"address":"bc1q","amount":` + a + `,"confirmations":6,"scriptPubKey":"0014"}`
	}
	c, err := NewBTCClient(cannedTransport{result: "[" + strings.Join(outs, ",") + "]"})
	if err != nil {
		t.Fatal(err)
	}
	return c.ListUnspent(context.Background(), "bc1q")
}

// The satoshi value ListUnspent answers becomes an escrow's funded amount and
// the input amount a segwit signature commits to, so every decimal amount a
// node reports must convert exactly.
func TestListUnspentConvertsAmountsToExactSatoshis(t *testing.T) {
	cases := map[string]int64{
		"0.29000000":        29_000_000,
		"0.57":              57_000_000,
		"0.00000003":        3,
		"1.1":               110_000_000,
		"20999999.99999999": 2_099_999_999_999_999,
		"1e-8":              1,
		"0":                 0,
	}
	for amount, want := range cases {
		utxos, err := listUnspentOf(t, amount)
		if err != nil {
			t.Fatalf("amount %s: %v", amount, err)
		}
		if len(utxos) != 1 || utxos[0].Value == nil || utxos[0].Value.Int64() != want {
			t.Fatalf("amount %s: got %v satoshis, want %d", amount, utxos[0].Value, want)
		}
	}
}

// An amount that cannot be a satoshi count is refused for its reason, never
// rounded.
func TestListUnspentRefusesAmountsThatAreNotWholeSatoshis(t *testing.T) {
	for amount, reason := range map[string]string{
		"0.123456789":       "more than eight decimal places",
		"-0.5":              "negative",
		"21000000.00000001": "exceeds the 21 million BTC",
		"1e999":             "exponent out of range",
		"0.0000000100000000000000000000000000000000": "too long",
		`"0.1x"`: "decode listunspent",
	} {
		utxos, err := listUnspentOf(t, amount)
		if err == nil {
			t.Fatalf("amount %s: accepted as %v, want a refusal", amount, utxos[0].Value)
		}
		if !strings.Contains(err.Error(), reason) {
			t.Fatalf("amount %s: refused with %q, want the reason %q", amount, err, reason)
		}
	}
}

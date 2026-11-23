/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package btc_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/bbmumford/plutus/adapter/btc"
)

// testPubKey generates a fake 33-byte compressed public key for testing.
func testPubKey(seed byte) []byte {
	key := make([]byte, 33)
	key[0] = 0x02 // compressed key prefix
	for i := 1; i < 33; i++ {
		key[i] = seed
	}
	return key
}

func TestCreateEscrowScript(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, err := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)
	if err != nil {
		t.Fatalf("CreateEscrowScript failed: %v", err)
	}

	if len(script.Script) == 0 {
		t.Fatal("script is empty")
	}

	if len(script.BuyerPubKey) != 33 {
		t.Fatalf("buyer pubkey length: got %d, want 33", len(script.BuyerPubKey))
	}

	if !bytes.Equal(script.BuyerPubKey, buyer) {
		t.Fatal("buyer pubkey mismatch")
	}

	if !bytes.Equal(script.SellerPubKey, seller) {
		t.Fatal("seller pubkey mismatch")
	}

	if !bytes.Equal(script.ArbitratorPubKey, arbitrator) {
		t.Fatal("arbitrator pubkey mismatch")
	}

	if script.TimeoutBlocks != 100000 {
		t.Fatalf("timeout blocks: got %d, want 100000", script.TimeoutBlocks)
	}

	// Verify script hash is SHA256 of script.
	expected := sha256.Sum256(script.Script)
	if script.ScriptHash != expected {
		t.Fatal("script hash mismatch")
	}
}

func TestCreateEscrowScriptDeterministic(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script1, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)
	script2, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)

	if !bytes.Equal(script1.Script, script2.Script) {
		t.Fatal("scripts should be deterministic")
	}

	if script1.ScriptHash != script2.ScriptHash {
		t.Fatal("script hashes should match")
	}
}

func TestCreateEscrowScriptDifferentParams(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script1, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)
	script2, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 200000)

	if bytes.Equal(script1.Script, script2.Script) {
		t.Fatal("different timeout should produce different scripts")
	}
}

func TestCreateEscrowScriptInvalidPubkey(t *testing.T) {
	buyer := make([]byte, 32) // wrong length
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	_, err := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)
	if err == nil {
		t.Fatal("expected error for invalid buyer pubkey length")
	}
}

func TestCreateEscrowScriptZeroTimeout(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	_, err := btc.CreateEscrowScript(buyer, seller, arbitrator, 0)
	if err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestP2WSHAddress(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)
	addr := script.P2WSHAddress()

	if len(addr) != 32 {
		t.Fatalf("P2WSH witness program length: got %d, want 32", len(addr))
	}

	// Must match script hash.
	if !bytes.Equal(addr, script.ScriptHash[:]) {
		t.Fatal("P2WSH address should be the script hash")
	}
}

func TestMultisigWitness(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)

	sig1 := make([]byte, 72) // DER-encoded signature placeholder
	sig2 := make([]byte, 72)

	witness, err := script.MultisigWitness(sig1, sig2)
	if err != nil {
		t.Fatalf("MultisigWitness failed: %v", err)
	}

	// Witness stack: <empty> <sig1> <sig2> <TRUE> <script>
	if len(witness) != 5 {
		t.Fatalf("witness stack length: got %d, want 5", len(witness))
	}

	if len(witness[0]) != 0 {
		t.Fatal("first witness element should be empty (OP_0 dummy)")
	}

	if !bytes.Equal(witness[1], sig1) {
		t.Fatal("sig1 mismatch")
	}

	if !bytes.Equal(witness[2], sig2) {
		t.Fatal("sig2 mismatch")
	}

	if len(witness[3]) != 1 || witness[3][0] != 0x01 {
		t.Fatal("fourth element should be TRUE (0x01)")
	}

	if !bytes.Equal(witness[4], script.Script) {
		t.Fatal("last witness element should be the script")
	}
}

func TestMultisigWitnessEmptySignature(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)

	_, err := script.MultisigWitness(nil, make([]byte, 72))
	if err == nil {
		t.Fatal("expected error for empty sig1")
	}
}

func TestTimeoutWitness(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)

	buyerSig := make([]byte, 72)

	witness, err := script.TimeoutWitness(buyerSig)
	if err != nil {
		t.Fatalf("TimeoutWitness failed: %v", err)
	}

	// Witness stack: <buyerSig> <FALSE> <script>
	if len(witness) != 3 {
		t.Fatalf("witness stack length: got %d, want 3", len(witness))
	}

	if !bytes.Equal(witness[0], buyerSig) {
		t.Fatal("buyer sig mismatch")
	}

	if len(witness[1]) != 0 {
		t.Fatal("second element should be empty (FALSE)")
	}

	if !bytes.Equal(witness[2], script.Script) {
		t.Fatal("last witness element should be the script")
	}
}

func TestTimeoutWitnessEmptySig(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)

	_, err := script.TimeoutWitness(nil)
	if err == nil {
		t.Fatal("expected error for empty buyer signature")
	}
}

func TestValidateEscrowScript(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)
	timeout := uint32(100000)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, timeout)

	err := btc.ValidateEscrowScript(script.Script, buyer, seller, arbitrator, timeout)
	if err != nil {
		t.Fatalf("ValidateEscrowScript failed: %v", err)
	}
}

func TestValidateEscrowScriptMismatch(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)

	// Validate with wrong timeout.
	err := btc.ValidateEscrowScript(script.Script, buyer, seller, arbitrator, 200000)
	if err == nil {
		t.Fatal("expected error for mismatched script")
	}
}

func TestScriptStructure(t *testing.T) {
	buyer := testPubKey(0x01)
	seller := testPubKey(0x02)
	arbitrator := testPubKey(0x03)

	script, _ := btc.CreateEscrowScript(buyer, seller, arbitrator, 100000)

	// Verify script starts with OP_IF (0x63).
	if script.Script[0] != 0x63 {
		t.Fatalf("script should start with OP_IF (0x63), got 0x%02x", script.Script[0])
	}

	// Verify OP_2 follows (0x52).
	if script.Script[1] != 0x52 {
		t.Fatalf("expected OP_2 (0x52) at byte 1, got 0x%02x", script.Script[1])
	}

	// Verify script ends with OP_ENDIF (0x68).
	lastByte := script.Script[len(script.Script)-1]
	if lastByte != 0x68 {
		t.Fatalf("script should end with OP_ENDIF (0x68), got 0x%02x", lastByte)
	}
}

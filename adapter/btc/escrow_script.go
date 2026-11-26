/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package btc

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// Bitcoin Script opcodes used in escrow scripts.
const (
	opDup                 = 0x76
	opHash160             = 0xa9
	opEqualVerify         = 0x88
	opCheckSig            = 0xac
	opCheckMultiSig       = 0xae
	op2                   = 0x52
	op3                   = 0x53
	opEqual               = 0x87
	op0                   = 0x00
	opIf                  = 0x63
	opElse                = 0x67
	opEndIf               = 0x68
	opCheckLocktimeVerify = 0xb1
	opDrop                = 0x75
	opCheckSequenceVerify = 0xb2
	opPushData1           = 0x4c
)

// EscrowScript represents a P2WSH 2-of-3 multisig escrow script.
// The three keys are buyer, seller, and arbitrator.
//
// Script semantics:
//   - Any 2 of the 3 keys can sign to spend
//   - After timeoutBlocks, buyer can unilaterally refund (CLTV)
//
// Script structure:
//
//	OP_IF
//	    OP_2 <buyer> <seller> <arbitrator> OP_3 OP_CHECKMULTISIG
//	OP_ELSE
//	    <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
//	    <buyer> OP_CHECKSIG
//	OP_ENDIF
type EscrowScript struct {
	// BuyerPubKey is the compressed public key of the buyer (33 bytes).
	BuyerPubKey []byte
	// SellerPubKey is the compressed public key of the seller (33 bytes).
	SellerPubKey []byte
	// ArbitratorPubKey is the compressed public key of the arbitrator (33 bytes).
	ArbitratorPubKey []byte
	// TimeoutBlocks is the CLTV block height after which the buyer can refund.
	TimeoutBlocks uint32
	// Script is the compiled witness script bytes.
	Script []byte
	// ScriptHash is the SHA256 hash of the script (used in P2WSH).
	ScriptHash [32]byte
}

// CreateEscrowScript builds a P2WSH 2-of-3 multisig escrow script with
// a CLTV timeout clause for buyer refund.
//
// The script allows:
//  1. Normal path: 2-of-3 multisig (buyer+seller, buyer+arbitrator, or seller+arbitrator)
//  2. Timeout path: buyer-only refund after timeoutBlocks
func CreateEscrowScript(buyerPubKey, sellerPubKey, arbitratorPubKey []byte, timeoutBlocks uint32) (*EscrowScript, error) {
	// Validate compressed public keys (33 bytes each).
	if len(buyerPubKey) != 33 {
		return nil, fmt.Errorf("btc/escrow: buyer pubkey must be 33 bytes (compressed), got %d", len(buyerPubKey))
	}
	if len(sellerPubKey) != 33 {
		return nil, fmt.Errorf("btc/escrow: seller pubkey must be 33 bytes (compressed), got %d", len(sellerPubKey))
	}
	if len(arbitratorPubKey) != 33 {
		return nil, fmt.Errorf("btc/escrow: arbitrator pubkey must be 33 bytes (compressed), got %d", len(arbitratorPubKey))
	}
	if timeoutBlocks == 0 {
		return nil, errors.New("btc/escrow: timeout blocks must be > 0")
	}

	// Build the script.
	script := buildEscrowScript(buyerPubKey, sellerPubKey, arbitratorPubKey, timeoutBlocks)

	// Compute SHA256 hash for P2WSH.
	scriptHash := sha256.Sum256(script)

	return &EscrowScript{
		BuyerPubKey:      buyerPubKey,
		SellerPubKey:     sellerPubKey,
		ArbitratorPubKey: arbitratorPubKey,
		TimeoutBlocks:    timeoutBlocks,
		Script:           script,
		ScriptHash:       scriptHash,
	}, nil
}

// buildEscrowScript compiles the raw script bytes.
//
//	OP_IF
//	    OP_2 <buyer> <seller> <arbitrator> OP_3 OP_CHECKMULTISIG
//	OP_ELSE
//	    <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
//	    <buyer> OP_CHECKSIG
//	OP_ENDIF
func buildEscrowScript(buyer, seller, arbitrator []byte, timeout uint32) []byte {
	script := make([]byte, 0, 256)

	// OP_IF — multisig path.
	script = append(script, opIf)

	// OP_2 (required signatures).
	script = append(script, op2)

	// Push buyer pubkey (33 bytes).
	script = append(script, 33) // push data length
	script = append(script, buyer...)

	// Push seller pubkey.
	script = append(script, 33)
	script = append(script, seller...)

	// Push arbitrator pubkey.
	script = append(script, 33)
	script = append(script, arbitrator...)

	// OP_3 (total keys) OP_CHECKMULTISIG.
	script = append(script, op3)
	script = append(script, opCheckMultiSig)

	// OP_ELSE — timeout refund path.
	script = append(script, opElse)

	// Push timeout value (as minimal encoding for Script numbers).
	timeoutBytes := encodeScriptNumber(int64(timeout))
	script = append(script, byte(len(timeoutBytes))) // push data length
	script = append(script, timeoutBytes...)

	// OP_CHECKLOCKTIMEVERIFY OP_DROP.
	script = append(script, opCheckLocktimeVerify)
	script = append(script, opDrop)

	// Push buyer pubkey for unilateral refund.
	script = append(script, 33)
	script = append(script, buyer...)

	// OP_CHECKSIG.
	script = append(script, opCheckSig)

	// OP_ENDIF.
	script = append(script, opEndIf)

	return script
}

// P2WSHAddress computes the P2WSH witness program for the escrow script.
// Returns the 32-byte witness program (SHA256 of the script).
// The full bech32 address encoding is chain-specific and handled by the
// wallet layer.
func (e *EscrowScript) P2WSHAddress() []byte {
	return e.ScriptHash[:]
}

// MultisigWitness constructs the witness stack for the 2-of-3 multisig
// spending path. The signatures must be ordered to match the pubkey order
// in the script (buyer, seller, arbitrator).
//
// Witness stack for P2WSH multisig:
//
//	<empty> <sig1> <sig2> <TRUE> <redeemScript>
func (e *EscrowScript) MultisigWitness(sig1, sig2 []byte) ([][]byte, error) {
	if len(sig1) == 0 || len(sig2) == 0 {
		return nil, errors.New("btc/escrow: both signatures are required for multisig spend")
	}

	return [][]byte{
		{},       // OP_0 dummy for CHECKMULTISIG bug
		sig1,     // first signature
		sig2,     // second signature
		{0x01},   // OP_TRUE to select the IF branch
		e.Script, // witness script (redeemScript)
	}, nil
}

// TimeoutWitness constructs the witness stack for the buyer timeout
// refund path. Only the buyer's signature is needed.
//
// Witness stack:
//
//	<buyerSig> <FALSE> <redeemScript>
func (e *EscrowScript) TimeoutWitness(buyerSig []byte) ([][]byte, error) {
	if len(buyerSig) == 0 {
		return nil, errors.New("btc/escrow: buyer signature is required for timeout refund")
	}

	return [][]byte{
		buyerSig, // buyer's signature
		{},       // OP_FALSE to select the ELSE branch
		e.Script, // witness script
	}, nil
}

// encodeScriptNumber encodes an integer for use in Bitcoin Script.
// Uses the minimal encoding required by BIP62/BIP341.
func encodeScriptNumber(n int64) []byte {
	if n == 0 {
		return []byte{}
	}

	negative := n < 0
	if negative {
		n = -n
	}

	result := make([]byte, 0, 8)
	for n > 0 {
		result = append(result, byte(n&0xff))
		n >>= 8
	}

	// If the high bit is set, add a sign byte.
	if result[len(result)-1]&0x80 != 0 {
		if negative {
			result = append(result, 0x80)
		} else {
			result = append(result, 0x00)
		}
	} else if negative {
		result[len(result)-1] |= 0x80
	}

	return result
}

// ValidateEscrowScript verifies that a script matches the expected structure
// and public keys.
func ValidateEscrowScript(script []byte, buyer, seller, arbitrator []byte, timeout uint32) error {
	expected := buildEscrowScript(buyer, seller, arbitrator, timeout)
	if len(script) != len(expected) {
		return fmt.Errorf("btc/escrow: script length mismatch: got %d, expected %d", len(script), len(expected))
	}
	for i := range script {
		if script[i] != expected[i] {
			return fmt.Errorf("btc/escrow: script mismatch at byte %d", i)
		}
	}
	return nil
}

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package wallet

import (
	"bytes"
	"testing"
)

func TestEncodeDecodePRCData_Roundtrip(t *testing.T) {
	t.Parallel()
	orig := &PRCData{
		MaintainerPayout:     "0x00000000000000000000000000000000deadbeef",
		MaintainerFeeBPS:     250,
		WitnessBPS:           50,
		MaintainerPubKeyHash: bytes.Repeat([]byte{0xAB}, 32),
	}
	raw, err := EncodePRCData(orig)
	if err != nil {
		t.Fatalf("EncodePRCData: %v", err)
	}
	if len(raw) != 60 {
		t.Errorf("encoded length: got %d, want 60", len(raw))
	}
	decoded, err := decodePRCData(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.MaintainerFeeBPS != orig.MaintainerFeeBPS {
		t.Errorf("MaintainerFeeBPS mismatch")
	}
	if decoded.WitnessBPS != orig.WitnessBPS {
		t.Errorf("WitnessBPS mismatch")
	}
	if !bytes.Equal(decoded.MaintainerPubKeyHash, orig.MaintainerPubKeyHash) {
		t.Errorf("pubkey hash mismatch")
	}
}

func TestDecodePRCData_TooShort(t *testing.T) {
	t.Parallel()
	if _, err := decodePRCData([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for short data")
	}
}

func TestEncodePRCData_BadHash(t *testing.T) {
	t.Parallel()
	if _, err := EncodePRCData(&PRCData{MaintainerPubKeyHash: []byte{1}}); err == nil {
		t.Error("expected error for short pubkey hash")
	}
}

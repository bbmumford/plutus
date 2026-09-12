/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package witness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// writeTestKeyfile writes a plaintext under passphrase to path in the
// canonical wallet-keyfile format. Mirrors wallet.WriteEncryptedKeyfile so
// the tests don't depend on the wallet package (which would pull in
// adapter/btc and defeat the cycle-break we carefully engineered).
func writeTestKeyfile(t *testing.T, path string, passphrase, plaintext []byte) {
	t.Helper()
	var salt [keyfileSaltSize]byte
	var nonce [keyfileNonceSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatalf("random salt: %v", err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("random nonce: %v", err)
	}
	key := argon2.IDKey(passphrase, salt[:],
		keyfileArgon2Time, keyfileArgon2Memory, keyfileArgon2Threads, keyfileArgon2KeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("AEAD: %v", err)
	}
	ct := aead.Seal(nil, nonce[:], plaintext, []byte(keyfileAssociatedData))
	blob := make([]byte, 0, keyfileSaltSize+keyfileNonceSize+len(ct))
	blob = append(blob, salt[:]...)
	blob = append(blob, nonce[:]...)
	blob = append(blob, ct...)
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
}

// newTestPriv returns a deterministic 32-byte secp256k1 scalar seeded from
// label. Using a hash of the label keeps fixtures stable across runs.
func newTestPriv(label string) []byte {
	h := keccak256([]byte(label))
	// Ensure non-zero (extremely unlikely with keccak but defensive).
	if bytes.Equal(h[:], make([]byte, 32)) {
		h[31] = 1
	}
	return append([]byte(nil), h[:]...)
}

// --- Config validation ----------------------------------------------------

func TestNewWalletSigner_EmptyConfig(t *testing.T) {
	if _, err := NewWalletSigner(WalletSignerConfig{}); err == nil {
		t.Fatal("want error for empty config, got nil")
	}
}

func TestNewWalletSigner_EmptyChainID(t *testing.T) {
	cfg := WalletSignerConfig{
		KeyFiles:    map[string]string{"": "somewhere"},
		Passphrases: map[string][]byte{"": nil},
	}
	_, err := NewWalletSigner(cfg)
	if err == nil {
		t.Fatal("want error for empty chain id, got nil")
	}
	if !strings.Contains(err.Error(), "empty chain ID") {
		t.Errorf("expected empty-chain-id error, got %v", err)
	}
}

func TestNewWalletSigner_EmptyPath(t *testing.T) {
	cfg := WalletSignerConfig{
		KeyFiles:    map[string]string{"bitcoin": ""},
		Passphrases: map[string][]byte{"bitcoin": nil},
	}
	_, err := NewWalletSigner(cfg)
	if err == nil {
		t.Fatal("want error for empty path, got nil")
	}
	if !strings.Contains(err.Error(), "empty key file path") {
		t.Errorf("expected empty-path error, got %v", err)
	}
}

func TestNewWalletSigner_MissingPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	writeTestKeyfile(t, path, []byte("pw"), newTestPriv("missing-pass"))
	cfg := WalletSignerConfig{
		KeyFiles:    map[string]string{"bitcoin": path},
		Passphrases: map[string][]byte{}, // no entry for bitcoin
	}
	_, err := NewWalletSigner(cfg)
	if err == nil {
		t.Fatal("want error for missing passphrase, got nil")
	}
	if !strings.Contains(err.Error(), "no passphrase") {
		t.Errorf("expected missing-passphrase error, got %v", err)
	}
}

func TestNewWalletSigner_BadPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	writeTestKeyfile(t, path, []byte("correct"), newTestPriv("bad-pass"))
	cfg := WalletSignerConfig{
		KeyFiles:    map[string]string{"bitcoin": path},
		Passphrases: map[string][]byte{"bitcoin": []byte("wrong")},
	}
	_, err := NewWalletSigner(cfg)
	if err == nil {
		t.Fatal("want error for bad passphrase, got nil")
	}
}

func TestNewWalletSigner_WrongKeyLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	// 16-byte plaintext is not a valid secp256k1 scalar.
	writeTestKeyfile(t, path, []byte("pw"), []byte("0123456789abcdef"))
	cfg := WalletSignerConfig{
		KeyFiles:    map[string]string{"bitcoin": path},
		Passphrases: map[string][]byte{"bitcoin": []byte("pw")},
	}
	_, err := NewWalletSigner(cfg)
	if err == nil {
		t.Fatal("want error for wrong key length, got nil")
	}
	if !strings.Contains(err.Error(), "want 32") {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestNewWalletSigner_Happy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "btc.key")
	writeTestKeyfile(t, path, []byte("pw"), newTestPriv("happy"))
	cfg := WalletSignerConfig{
		KeyFiles:    map[string]string{"bitcoin": path},
		Passphrases: map[string][]byte{"bitcoin": []byte("pw")},
	}
	s, err := NewWalletSigner(cfg)
	if err != nil {
		t.Fatalf("NewWalletSigner: %v", err)
	}
	if _, ok := s.perChainKeys["bitcoin"]; !ok {
		t.Error("bitcoin key not stored")
	}
}

// --- Dispatch error cases -------------------------------------------------

func TestSignBatchPayout_UnknownKind(t *testing.T) {
	s := newTestSigner(t, "bitcoin", newTestPriv("unk"))
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID: "bitcoin",
		Kind:    BatchKind(99),
	})
	if err == nil {
		t.Fatal("want error for unknown kind, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported batch kind") {
		t.Errorf("expected unsupported kind error, got %v", err)
	}
}

func TestSignBatchPayout_UnspecifiedKind(t *testing.T) {
	s := newTestSigner(t, "bitcoin", newTestPriv("u"))
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID: "bitcoin",
		Kind:    BatchKindUnspecified,
	})
	if err == nil {
		t.Fatal("want error for unspecified kind")
	}
}

func TestSignBatchPayout_MissingKey(t *testing.T) {
	s := newTestSigner(t, "bitcoin", newTestPriv("m"))
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID: "ethereum", // no key configured
		Kind:    BatchKindEVMMulticall3,
	})
	if err == nil {
		t.Fatal("want error for missing key")
	}
	if !strings.Contains(err.Error(), "no key configured") {
		t.Errorf("expected missing-key error, got %v", err)
	}
}

// --- BTC signing ----------------------------------------------------------

func TestSignBatchPayout_BTC_SighashWrongLength(t *testing.T) {
	s := newTestSigner(t, "bitcoin", newTestPriv("btc-short"))
	payload := buildTestBTCTx(t, 1)
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID:      "bitcoin",
		Kind:         BatchKindBTCMultiOutput,
		Payload:      payload,
		Sighashes:    [][]byte{make([]byte, 31)}, // one byte short
		InputScripts: [][]byte{make([]byte, 25)},
		InputValues:  []int64{1000},
	})
	if err == nil {
		t.Fatal("want error for short sighash")
	}
	if !strings.Contains(err.Error(), "want 32") {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestSignBatchPayout_BTC_InputScriptLengthMismatch(t *testing.T) {
	s := newTestSigner(t, "bitcoin", newTestPriv("btc-mis"))
	payload := buildTestBTCTx(t, 2)
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID:      "bitcoin",
		Kind:         BatchKindBTCMultiOutput,
		Payload:      payload,
		Sighashes:    [][]byte{make([]byte, 32), make([]byte, 32)},
		InputScripts: [][]byte{make([]byte, 25)}, // missing second
		InputValues:  []int64{1000, 2000},
	})
	if err == nil {
		t.Fatal("want error for length mismatch")
	}
}

func TestSignBatchPayout_BTC_Valid(t *testing.T) {
	priv := newTestPriv("btc-valid")
	s := newTestSigner(t, "bitcoin", priv)

	numInputs := 2
	payload := buildTestBTCTx(t, numInputs)

	// Fabricate 32-byte sighashes. We don't need these to match a real
	// BIP143 preimage — the signer treats them as opaque digests and the
	// test only verifies the resulting witness stack is well-formed ECDSA
	// against the known pubkey.
	sighashes := make([][]byte, numInputs)
	for i := range sighashes {
		h := keccak256([]byte{byte('s'), byte(i)})
		sighashes[i] = append([]byte(nil), h[:]...)
	}
	inputScripts := [][]byte{make([]byte, 25), make([]byte, 25)}
	inputValues := []int64{100_000, 200_000}

	batch := UnsignedBatch{
		ChainID:      "bitcoin",
		Kind:         BatchKindBTCMultiOutput,
		Payload:      payload,
		Sighashes:    sighashes,
		InputScripts: inputScripts,
		InputValues:  inputValues,
	}
	out, err := s.SignBatchPayout(context.Background(), batch)
	if err != nil {
		t.Fatalf("SignBatchPayout: %v", err)
	}
	if out.ChainID != "bitcoin" {
		t.Errorf("ChainID=%q want bitcoin", out.ChainID)
	}
	if len(out.Txs) != 1 {
		t.Fatalf("Txs=%d want 1", len(out.Txs))
	}

	// Parse the signed tx and verify each input witness has 2 items whose
	// signature decodes as DER, ends in SIGHASH_ALL, and verifies against
	// the expected pubkey.
	signedTx, err := parseSignedBTCTx(out.Txs[0])
	if err != nil {
		t.Fatalf("parse signed tx: %v", err)
	}
	if len(signedTx.txIn) != numInputs {
		t.Fatalf("signed txIn=%d want %d", len(signedTx.txIn), numInputs)
	}
	sk := secp256k1.PrivKeyFromBytes(priv)
	wantPub := sk.PubKey()
	for i, in := range signedTx.txIn {
		if len(in.witness) != 2 {
			t.Fatalf("input %d witness items=%d want 2", i, len(in.witness))
		}
		sigBytes := in.witness[0]
		pubBytes := in.witness[1]
		if len(sigBytes) < 2 || sigBytes[len(sigBytes)-1] != btcSighashAll {
			t.Errorf("input %d witness sig missing SIGHASH_ALL", i)
		}
		if !bytes.Equal(pubBytes, wantPub.SerializeCompressed()) {
			t.Errorf("input %d witness pubkey mismatch", i)
		}
		parsedSig, err := ecdsa.ParseDERSignature(sigBytes[:len(sigBytes)-1])
		if err != nil {
			t.Errorf("input %d ParseDERSignature: %v", i, err)
			continue
		}
		if !parsedSig.Verify(sighashes[i], wantPub) {
			t.Errorf("input %d signature does not verify against known pubkey", i)
		}
	}
}

// --- EVM signing ----------------------------------------------------------

func TestSignBatchPayout_EVM_MissingNonce(t *testing.T) {
	s := newTestSigner(t, "ethereum", newTestPriv("evm-mn"))
	env := buildTestEVMEnvelope(t, 1, false /* no nonce */, true /* gas */)
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID: "ethereum",
		Kind:    BatchKindEVMMulticall3,
		Payload: env,
	})
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("want nonce error, got %v", err)
	}
}

func TestSignBatchPayout_EVM_MissingGasPrice(t *testing.T) {
	s := newTestSigner(t, "ethereum", newTestPriv("evm-mg"))
	env := buildTestEVMEnvelope(t, 1, true /* nonce */, false /* no gas */)
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID: "ethereum",
		Kind:    BatchKindEVMMulticall3,
		Payload: env,
	})
	if err == nil || !strings.Contains(err.Error(), "gas price") {
		t.Fatalf("want gas price error, got %v", err)
	}
}

func TestSignBatchPayout_EVM_ZeroChainID(t *testing.T) {
	s := newTestSigner(t, "ethereum", newTestPriv("evm-zc"))
	// Envelope with chainID=0.
	env := []byte(`{"to":"0x0000000000000000000000000000000000000001","value":"0x0","data":"0x","gasLimit":21000,"evmChainID":0,"nonce":1,"nonceSet":true,"gasPrice":"0x3b9aca00"}`)
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID: "ethereum",
		Kind:    BatchKindEVMMulticall3,
		Payload: env,
	})
	if err == nil || !strings.Contains(err.Error(), "chain ID") {
		t.Fatalf("want chain id error, got %v", err)
	}
}

func TestSignBatchPayout_EVM_Valid(t *testing.T) {
	priv := newTestPriv("evm-valid")
	s := newTestSigner(t, "ethereum", priv)

	expectedFrom, err := evmAddressFromPrivKey(priv)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}

	env := buildTestEVMEnvelope(t, 1 /* chainID */, true, true)
	out, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID: "ethereum",
		Kind:    BatchKindEVMMulticall3,
		Payload: env,
	})
	if err != nil {
		t.Fatalf("SignBatchPayout: %v", err)
	}
	if len(out.Txs) != 1 {
		t.Fatalf("Txs=%d want 1", len(out.Txs))
	}

	// Verify the signed tx recovers to the expected sender address.
	sender, err := recoverEIP155Sender(out.Txs[0])
	if err != nil {
		t.Fatalf("recover sender: %v", err)
	}
	if !strings.EqualFold(sender, expectedFrom) {
		t.Errorf("recovered sender=%s want %s", sender, expectedFrom)
	}
}

// --- EVM individual-mode signing -----------------------------------------

// buildIndividualEVMEnvelope returns a minimal per-item EVM envelope with the
// given chain ID and nonce. Used to stand up BatchKindEVMIndividual batches
// without pulling in the adapter/evm package (which would form an import
// cycle — the witness package is a dependency of adapter/evm).
func buildIndividualEVMEnvelope(t *testing.T, chainID uint64, nonce uint64, toAddr string, value *big.Int) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"to":"`)
	b.WriteString(toAddr)
	b.WriteString(`","value":"0x`)
	if value != nil && value.Sign() > 0 {
		b.WriteString(value.Text(16))
	} else {
		b.WriteString("0")
	}
	b.WriteString(`","data":"0x","gasLimit":61000,"evmChainID":`)
	b.WriteString(bigIntToDec(chainID))
	b.WriteString(`,"nonce":`)
	b.WriteString(bigIntToDec(nonce))
	b.WriteString(`,"nonceSet":true,"gasPrice":"0x3b9aca00"}`)
	return []byte(b.String())
}

func TestSignBatchPayout_EVMIndividual_HappyPath(t *testing.T) {
	priv := newTestPriv("evm-ind-happy")
	s := newTestSigner(t, "ethereum", priv)

	expectedFrom, err := evmAddressFromPrivKey(priv)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}

	// Three items with nonces 7, 8, 9 (simulating a finalizer that read
	// startNonce=7 from the chain).
	recipients := []string{
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
		"0x3333333333333333333333333333333333333333",
	}
	items := make([][]byte, len(recipients))
	for i, to := range recipients {
		items[i] = buildIndividualEVMEnvelope(t, 1, uint64(7+i), to, big.NewInt(int64(1000*(i+1))))
	}

	out, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID:      "ethereum",
		Kind:         BatchKindEVMIndividual,
		ItemPayloads: items,
	})
	if err != nil {
		t.Fatalf("SignBatchPayout: %v", err)
	}
	if out.ChainID != "ethereum" {
		t.Errorf("ChainID=%q want ethereum", out.ChainID)
	}
	if len(out.Txs) != len(items) {
		t.Fatalf("Txs=%d want %d", len(out.Txs), len(items))
	}

	// Each tx must be distinct wire bytes, recover to the pool wallet, and
	// carry the nonce we injected.
	seen := make(map[string]bool, len(out.Txs))
	for i, raw := range out.Txs {
		sender, err := recoverEIP155Sender(raw)
		if err != nil {
			t.Fatalf("item %d recover sender: %v", i, err)
		}
		if !strings.EqualFold(sender, expectedFrom) {
			t.Errorf("item %d recovered sender=%s want %s", i, sender, expectedFrom)
		}
		fields, err := decodeRLPList(raw)
		if err != nil {
			t.Fatalf("item %d decode rlp: %v", i, err)
		}
		if len(fields) != 9 {
			t.Fatalf("item %d rlp fields=%d want 9", i, len(fields))
		}
		gotNonce := bytesToUint64(fields[0])
		wantNonce := uint64(7 + i)
		if gotNonce != wantNonce {
			t.Errorf("item %d nonce=%d want %d", i, gotNonce, wantNonce)
		}
		key := hex.EncodeToString(raw)
		if seen[key] {
			t.Errorf("item %d produced a duplicate signed tx", i)
		}
		seen[key] = true
	}
}

func TestSignBatchPayout_EVMIndividual_EmptyItems(t *testing.T) {
	s := newTestSigner(t, "ethereum", newTestPriv("evm-ind-empty"))
	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID:      "ethereum",
		Kind:         BatchKindEVMIndividual,
		ItemPayloads: nil,
	})
	if err == nil {
		t.Fatal("want error for empty ItemPayloads")
	}
	if !strings.Contains(err.Error(), "no ItemPayloads") {
		t.Errorf("expected no-ItemPayloads error, got %v", err)
	}
}

func TestSignBatchPayout_EVMIndividual_InvalidMiddleItem(t *testing.T) {
	s := newTestSigner(t, "ethereum", newTestPriv("evm-ind-bad"))
	good1 := buildIndividualEVMEnvelope(t, 1, 1, "0x1111111111111111111111111111111111111111", big.NewInt(100))
	good3 := buildIndividualEVMEnvelope(t, 1, 3, "0x3333333333333333333333333333333333333333", big.NewInt(300))
	// Middle item: missing nonce → signer must reject the whole batch.
	bad := buildTestEVMEnvelope(t, 1, false /* no nonce */, true /* gas */)

	_, err := s.SignBatchPayout(context.Background(), UnsignedBatch{
		ChainID:      "ethereum",
		Kind:         BatchKindEVMIndividual,
		ItemPayloads: [][]byte{good1, bad, good3},
	})
	if err == nil {
		t.Fatal("want error when middle item is invalid")
	}
	if !strings.Contains(err.Error(), "item 1") {
		t.Errorf("expected error to identify item 1, got %v", err)
	}
}

// --- helpers --------------------------------------------------------------

// newTestSigner constructs a WalletSigner by writing `priv` to an encrypted
// keyfile and loading it. Exercises the same NewWalletSigner code path as
// production.
func newTestSigner(t *testing.T, chainID string, priv []byte) *WalletSigner {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, chainID+".key")
	writeTestKeyfile(t, path, []byte("pw"), priv)
	s, err := NewWalletSigner(WalletSignerConfig{
		KeyFiles:    map[string]string{chainID: path},
		Passphrases: map[string][]byte{chainID: []byte("pw")},
	})
	if err != nil {
		t.Fatalf("NewWalletSigner: %v", err)
	}
	return s
}

// buildTestBTCTx serializes a minimal unsigned BTC tx with `n` inputs and 1
// output suitable for the WalletSigner's parser.
func buildTestBTCTx(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	// Version = 2.
	_ = binary.Write(&buf, binary.LittleEndian, int32(2))
	// Input count (single-byte varint — tests use n < 253).
	if n >= 253 {
		t.Fatalf("buildTestBTCTx only supports n < 253, got %d", n)
	}
	buf.WriteByte(byte(n))
	for i := 0; i < n; i++ {
		var hash [32]byte
		hash[0] = byte(i + 1)
		buf.Write(hash[:])
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // vout
		buf.WriteByte(0)                                       // empty sigScript
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFE))
	}
	// Output count.
	buf.WriteByte(1)
	_ = binary.Write(&buf, binary.LittleEndian, int64(500_000))
	// 22-byte P2WPKH scriptPubKey: 0x00 0x14 || 20 bytes.
	buf.WriteByte(22)
	buf.WriteByte(0x00)
	buf.WriteByte(0x14)
	buf.Write(bytes.Repeat([]byte{0xbb}, 20))
	// LockTime = 0.
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

// parseSignedBTCTx parses the BIP141 segwit-serialized form emitted by the
// WalletSigner back into a btcMsgTx suitable for witness-stack inspection.
func parseSignedBTCTx(raw []byte) (*btcMsgTx, error) {
	if len(raw) < 10 {
		return nil, newErr("tx too short")
	}
	tx := &btcMsgTx{}
	pos := 0
	tx.version = int32(binary.LittleEndian.Uint32(raw[pos : pos+4]))
	pos += 4

	hasWitness := false
	if pos+1 < len(raw) && raw[pos] == 0x00 && raw[pos+1] == 0x01 {
		hasWitness = true
		pos += 2
	}

	inCount, n, err := readVarInt(raw[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	for i := uint64(0); i < inCount; i++ {
		var in btcTxIn
		copy(in.prevHash[:], raw[pos:pos+32])
		pos += 32
		in.prevIndex = binary.LittleEndian.Uint32(raw[pos : pos+4])
		pos += 4
		sigLen, n, err := readVarInt(raw[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		if sigLen > 0 {
			in.sigScript = append([]byte(nil), raw[pos:pos+int(sigLen)]...)
		}
		pos += int(sigLen)
		in.sequence = binary.LittleEndian.Uint32(raw[pos : pos+4])
		pos += 4
		tx.txIn = append(tx.txIn, &in)
	}

	outCount, n, err := readVarInt(raw[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	for i := uint64(0); i < outCount; i++ {
		val := int64(binary.LittleEndian.Uint64(raw[pos : pos+8]))
		pos += 8
		pkLen, n, err := readVarInt(raw[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		pk := append([]byte(nil), raw[pos:pos+int(pkLen)]...)
		pos += int(pkLen)
		tx.txOut = append(tx.txOut, &btcTxOut{value: val, pkScript: pk})
	}

	if hasWitness {
		for i := range tx.txIn {
			witCount, n, err := readVarInt(raw[pos:])
			if err != nil {
				return nil, err
			}
			pos += n
			for j := uint64(0); j < witCount; j++ {
				itemLen, n, err := readVarInt(raw[pos:])
				if err != nil {
					return nil, err
				}
				pos += n
				item := append([]byte(nil), raw[pos:pos+int(itemLen)]...)
				pos += int(itemLen)
				tx.txIn[i].witness = append(tx.txIn[i].witness, item)
			}
		}
	}

	tx.lockTime = binary.LittleEndian.Uint32(raw[pos : pos+4])
	pos += 4
	if pos != len(raw) {
		return nil, newErr("trailing bytes")
	}
	return tx, nil
}

// buildTestEVMEnvelope builds a minimal EVM envelope with the given chain
// ID. nonceSet / gasSet toggle whether those fields are populated so tests
// can exercise the signer's validation branches.
func buildTestEVMEnvelope(t *testing.T, chainID uint64, nonceSet, gasSet bool) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"to":"0x00000000000000000000000000000000000000aa"`)
	b.WriteString(`,"value":"0x0"`)
	b.WriteString(`,"data":"0x"`)
	b.WriteString(`,"gasLimit":100000`)
	b.WriteString(`,"evmChainID":`)
	b.WriteString(bigIntToDec(chainID))
	if nonceSet {
		b.WriteString(`,"nonce":5,"nonceSet":true`)
	}
	if gasSet {
		b.WriteString(`,"gasPrice":"0x3b9aca00"`) // 1 gwei
	}
	b.WriteString(`}`)
	return []byte(b.String())
}

func bigIntToDec(n uint64) string {
	return new(big.Int).SetUint64(n).String()
}

// recoverEIP155Sender takes the raw signed tx bytes and recovers the sender
// address by re-deriving the EIP-155 preimage and verifying the signature
// via ecdsa.RecoverCompact. Returns the EIP-55 checksummed address hex.
func recoverEIP155Sender(raw []byte) (string, error) {
	items, err := decodeRLPList(raw)
	if err != nil {
		return "", err
	}
	if len(items) != 9 {
		return "", newErr("expected 9-element tx")
	}
	// Fields: nonce, gasPrice, gasLimit, to, value, data, v, r, s
	nonce := bytesToUint64(items[0])
	gasPrice := new(big.Int).SetBytes(items[1])
	gasLimit := bytesToUint64(items[2])
	to := items[3] // 0 or 20 bytes
	value := new(big.Int).SetBytes(items[4])
	data := items[5]
	v := new(big.Int).SetBytes(items[6])
	r := new(big.Int).SetBytes(items[7])
	sVal := new(big.Int).SetBytes(items[8])

	// chainID = (v - 35) / 2
	vMinus35 := new(big.Int).Sub(v, big.NewInt(35))
	chainID := new(big.Int).Rsh(vMinus35, 1)
	recID := new(big.Int).Sub(vMinus35, new(big.Int).Mul(chainID, big.NewInt(2))).Int64()
	if recID != 0 && recID != 1 {
		return "", newErr("unexpected recovery id")
	}

	// Re-derive preimage and digest.
	preimage := rlpList(
		rlpUint(nonce),
		rlpBigInt(gasPrice),
		rlpUint(gasLimit),
		rlpBytes(to),
		rlpBigInt(value),
		rlpBytes(data),
		rlpBigInt(chainID),
		rlpUint(0),
		rlpUint(0),
	)
	digest := keccak256(preimage)

	// Build compact sig [27+recID, R, S].
	compact := make([]byte, 65)
	compact[0] = byte(27 + recID)
	rBytes := r.Bytes()
	sBytes := sVal.Bytes()
	copy(compact[1+(32-len(rBytes)):33], rBytes)
	copy(compact[33+(32-len(sBytes)):65], sBytes)

	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return "", err
	}
	pubBytes := pub.SerializeUncompressed()
	h := keccak256(pubBytes[1:])
	addr := h[12:]
	lower := hex.EncodeToString(addr)
	hashOfLower := keccak256([]byte(lower))
	hashHex := hex.EncodeToString(hashOfLower[:])
	out := make([]byte, 42)
	out[0] = '0'
	out[1] = 'x'
	for i := 0; i < 40; i++ {
		c := lower[i]
		if c >= 'a' && c <= 'f' && hashHex[i] >= '8' {
			out[i+2] = c - 32
		} else {
			out[i+2] = c
		}
	}
	return string(out), nil
}

// decodeRLPList parses a top-level RLP list and returns the byte-string
// contents of each child. Supports only the (nested-string) shape of a
// legacy Ethereum tx — no recursion into nested lists.
func decodeRLPList(raw []byte) ([][]byte, error) {
	if len(raw) == 0 {
		return nil, newErr("empty rlp")
	}
	b := raw[0]
	var body []byte
	switch {
	case b >= 0xc0 && b <= 0xf7:
		bodyLen := int(b - 0xc0)
		if 1+bodyLen > len(raw) {
			return nil, newErr("list truncated")
		}
		body = raw[1 : 1+bodyLen]
	case b >= 0xf8:
		lenLen := int(b - 0xf7)
		if 1+lenLen > len(raw) {
			return nil, newErr("list length truncated")
		}
		bodyLen := 0
		for i := 0; i < lenLen; i++ {
			bodyLen = bodyLen<<8 | int(raw[1+i])
		}
		if 1+lenLen+bodyLen > len(raw) {
			return nil, newErr("list body truncated")
		}
		body = raw[1+lenLen : 1+lenLen+bodyLen]
	default:
		return nil, newErr("not a list")
	}

	var items [][]byte
	for len(body) > 0 {
		item, rest, err := decodeRLPString(body)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		body = rest
	}
	return items, nil
}

func decodeRLPString(raw []byte) ([]byte, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, newErr("empty")
	}
	b := raw[0]
	switch {
	case b < 0x80:
		return []byte{b}, raw[1:], nil
	case b <= 0xb7:
		strLen := int(b - 0x80)
		if 1+strLen > len(raw) {
			return nil, nil, newErr("string truncated")
		}
		return raw[1 : 1+strLen], raw[1+strLen:], nil
	case b <= 0xbf:
		lenLen := int(b - 0xb7)
		if 1+lenLen > len(raw) {
			return nil, nil, newErr("string length truncated")
		}
		strLen := 0
		for i := 0; i < lenLen; i++ {
			strLen = strLen<<8 | int(raw[1+i])
		}
		if 1+lenLen+strLen > len(raw) {
			return nil, nil, newErr("string body truncated")
		}
		return raw[1+lenLen : 1+lenLen+strLen], raw[1+lenLen+strLen:], nil
	default:
		return nil, nil, newErr("not a string")
	}
}

func bytesToUint64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func newErr(msg string) error { return errorString(msg) }

type errorString string

func (e errorString) Error() string { return string(e) }

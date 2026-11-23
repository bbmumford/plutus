/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package canonical

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

// saveTrustChain captures current trust chain state for restore after mutations.
type savedTrustChain struct {
	or    []byte
	pc    []byte
	deps  map[string][]byte
	cps   map[string]string
	mhash []byte
	prc   map[string]string
}

func snapshot() *savedTrustChain {
	s := &savedTrustChain{
		or:    append([]byte(nil), TrustChain.OfflineRootPubKey...),
		pc:    append([]byte(nil), TrustChain.PlatformCert...),
		deps:  make(map[string][]byte),
		cps:   make(map[string]string),
		mhash: append([]byte(nil), MaintainerPubKeyHash...),
		prc:   make(map[string]string),
	}
	for k, v := range TrustChain.PRCDeployments {
		s.deps[k] = append([]byte(nil), v...)
	}
	for k, v := range TrustChain.Checkpoints {
		s.cps[k] = v
	}
	for k, v := range PRC {
		s.prc[k] = v
	}
	return s
}

func (s *savedTrustChain) restore() {
	TrustChain.OfflineRootPubKey = s.or
	TrustChain.PlatformCert = s.pc
	TrustChain.PRCDeployments = s.deps
	TrustChain.Checkpoints = s.cps
	MaintainerPubKeyHash = s.mhash
	// Reset PRC map keys in case tests changed them.
	for k := range PRC {
		delete(PRC, k)
	}
	for k, v := range s.prc {
		PRC[k] = v
	}
	// Trust chain inputs just changed — drop the cached VerifyTrustChain
	// result so the next caller re-runs the verification.
	resetTrustChainCache()
}

// installTestChain sets up a valid trust chain for testing and returns the
// platform private key so tests can sign adapters, etc.
func installTestChain(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	orPub, orPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate OR key: %v", err)
	}
	pkPub, pkPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate PK key: %v", err)
	}

	issued := time.Unix(1_700_000_000, 0).UTC()
	payload := computePlatformCertPayload(pkPub, orPub, issued)
	sig := ed25519.Sign(orPriv, payload)

	certJSON, _ := json.Marshal(platformKeyCertJSON{
		PlatformPubKey:    pkPub,
		OfflineRootPubKey: orPub,
		IssuedAt:          issued,
		Signature:         sig,
	})

	TrustChain.OfflineRootPubKey = orPub
	TrustChain.PlatformCert = certJSON
	TrustChain.PRCDeployments = make(map[string][]byte)
	TrustChain.Checkpoints = make(map[string]string)
	pkHash := sha256.Sum256(pkPub)
	MaintainerPubKeyHash = pkHash[:]

	// Freshly installed chain — clear any previously cached result so the
	// next VerifyTrustChain call evaluates against this new state.
	resetTrustChainCache()

	return pkPriv, pkPub
}

// BenchmarkVerifyTrustChain_Cached measures the cached (sync.Once) path.
// After the first call, subsequent calls return the memoized error and
// should be sub-microsecond. The first call's uncached cost is exercised
// by BenchmarkVerifyTrustChain_Uncached.
func BenchmarkVerifyTrustChain_Cached(b *testing.B) {
	saved := snapshot()
	defer saved.restore()

	// Install a valid chain then prime the cache with one call.
	pkPriv, _ := installTestChain(&testing.T{})
	installDeploymentCert(&testing.T{}, pkPriv, "ethereum", "0xABC")
	if err := VerifyTrustChain(); err != nil {
		b.Fatalf("prime VerifyTrustChain: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := VerifyTrustChain(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyTrustChain_Uncached measures the full verification cost
// by resetting the cache on every iteration. Represents pre-cache behaviour.
func BenchmarkVerifyTrustChain_Uncached(b *testing.B) {
	saved := snapshot()
	defer saved.restore()

	pkPriv, _ := installTestChain(&testing.T{})
	installDeploymentCert(&testing.T{}, pkPriv, "ethereum", "0xABC")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resetTrustChainCache()
		if err := VerifyTrustChain(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestIsCanonicalPRC(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	PRC["ethereum"] = "0xABCD"
	if !IsCanonicalPRC("ethereum", "0xabcd") {
		t.Error("case-insensitive match should succeed")
	}
	if IsCanonicalPRC("ethereum", "0xdead") {
		t.Error("wrong address should not be canonical")
	}
	if IsCanonicalPRC("unknown-chain", "0xabcd") {
		t.Error("unknown chain should not be canonical")
	}
}

func TestVerifyTrustChain_OK(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	installTestChain(t)

	if err := VerifyTrustChain(); err != nil {
		t.Fatalf("VerifyTrustChain with valid chain returned error: %v", err)
	}
}

func TestVerifyTrustChain_BadSignature(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	installTestChain(t)

	// Flip a byte in the signature.
	var cert platformKeyCertJSON
	if err := json.Unmarshal(TrustChain.PlatformCert, &cert); err != nil {
		t.Fatalf("unmarshal cert: %v", err)
	}
	cert.Signature[0] ^= 0xFF
	TrustChain.PlatformCert, _ = json.Marshal(cert)
	resetTrustChainCache()

	if err := VerifyTrustChain(); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestVerifyTrustChain_MismatchedMaintainerHash(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	installTestChain(t)

	// Set MaintainerPubKeyHash to a bogus value.
	MaintainerPubKeyHash = make([]byte, 32)
	resetTrustChainCache()

	err := VerifyTrustChain()
	if err == nil {
		t.Fatal("expected error for mismatched maintainer hash")
	}
	if !strings.Contains(err.Error(), "MaintainerPubKeyHash") {
		t.Errorf("expected mismatch error mentioning MaintainerPubKeyHash, got: %v", err)
	}
}

func TestVerifyTrustChain_MissingOR(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	TrustChain.OfflineRootPubKey = nil
	resetTrustChainCache()
	if err := VerifyTrustChain(); err == nil {
		t.Fatal("expected error for missing OR key")
	}
}

func TestProtocolFingerprint_Deterministic(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	installTestChain(t)
	// Reset the sync.Once guard by reassigning; our process-level cache
	// prevents re-derivation. Since tests run in a single process and we
	// cannot reset the sync.Once, we just assert that repeated calls match.
	fp1 := ProtocolFingerprint()
	fp2 := ProtocolFingerprint()
	if fp1 == "" {
		t.Fatal("fingerprint should be non-empty when trust chain is populated")
	}
	if fp1 != fp2 {
		t.Errorf("fingerprint mismatch across calls: %q vs %q", fp1, fp2)
	}
	if len(fp1) != 32 {
		t.Errorf("fingerprint should be 32 hex chars, got %d", len(fp1))
	}
}

func TestProtocolFingerprint_EmptyTrustChain(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	TrustChain.OfflineRootPubKey = nil
	if fp := ProtocolFingerprint(); fp != "" {
		t.Errorf("expected empty fingerprint with empty OR, got %q", fp)
	}
}

func TestWitnessTopic_UsesFingerprintPrefix(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	installTestChain(t)
	fp := ProtocolFingerprint()
	topic := WitnessTopic()
	if fp == "" {
		return
	}
	if !strings.HasPrefix(topic, "plutus."+fp[:8]+".") {
		t.Errorf("WitnessTopic %q should be prefixed with plutus.%s.", topic, fp[:8])
	}
	if !strings.HasSuffix(topic, ".witnesses") {
		t.Errorf("WitnessTopic %q should end with .witnesses", topic)
	}
}

// -- Adapter trust verification ---------------------------------------------

// signAdapter returns a signed descriptor JSON blob for testing.
func signAdapter(t *testing.T, platformPriv ed25519.PrivateKey, platformPub ed25519.PublicKey, chainID, prcAddr string) []byte {
	t.Helper()
	adapterHash := sha256.Sum256([]byte("adapter-bytes"))
	payload := computeAdapterPayload(chainID, "USDC", "USDC", "1.0", prcAddr, adapterHash[:])
	sig := ed25519.Sign(platformPriv, payload)

	desc := struct {
		ChainID      string `json:"chainID"`
		Currency     string `json:"currency"`
		Symbol       string `json:"symbol"`
		Version      string `json:"version"`
		PRCAddress   string `json:"prcAddress"`
		AdapterHash  []byte `json:"adapterHash"`
		SignerPubKey []byte `json:"signerPubKey"`
		Signature    []byte `json:"signature"`
	}{
		ChainID:      chainID,
		Currency:     "USDC",
		Symbol:       "USDC",
		Version:      "1.0",
		PRCAddress:   prcAddr,
		AdapterHash:  adapterHash[:],
		SignerPubKey: platformPub,
		Signature:    sig,
	}
	b, _ := json.Marshal(desc)
	return b
}

// installDeploymentCert installs a PRC deployment cert signed by the given
// platform key for the given chain and address.
func installDeploymentCert(t *testing.T, platformPriv ed25519.PrivateKey, chainID, prcAddr string) {
	t.Helper()
	deployedAt := time.Unix(1_700_000_100, 0).UTC()
	payload := computePRCDeploymentPayload(chainID, prcAddr, "tx-hash", 42, deployedAt)
	sig := ed25519.Sign(platformPriv, payload)

	dep := prcDeploymentCertJSON{
		ChainID:      chainID,
		PRCAddress:   prcAddr,
		DeployTxHash: "tx-hash",
		BlockNumber:  42,
		DeployedAt:   deployedAt,
		Signature:    sig,
	}
	b, _ := json.Marshal(dep)
	TrustChain.PRCDeployments[chainID] = b
	PRC[chainID] = prcAddr
}

func TestVerifyAdapterTrust_OK(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	pkPriv, pkPub := installTestChain(t)
	installDeploymentCert(t, pkPriv, "ethereum", "0xADAPTER")

	desc := signAdapter(t, pkPriv, pkPub, "ethereum", "0xADAPTER")
	if err := VerifyAdapterTrust(desc); err != nil {
		t.Fatalf("VerifyAdapterTrust happy path: %v", err)
	}
}

func TestVerifyAdapterTrust_BadSigner(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	pkPriv, _ := installTestChain(t)
	installDeploymentCert(t, pkPriv, "ethereum", "0xADAPTER")

	// Sign adapter with a DIFFERENT key, not the platform key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	desc := signAdapter(t, otherPriv, otherPub, "ethereum", "0xADAPTER")

	if err := VerifyAdapterTrust(desc); err == nil {
		t.Fatal("expected bad-signer error")
	}
}

func TestVerifyAdapterTrust_BadSignature(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	pkPriv, pkPub := installTestChain(t)
	installDeploymentCert(t, pkPriv, "ethereum", "0xADAPTER")

	desc := signAdapter(t, pkPriv, pkPub, "ethereum", "0xADAPTER")
	// Flip one byte of the signature in the JSON by re-marshalling.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(desc, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var sig []byte
	if err := json.Unmarshal(raw["signature"], &sig); err != nil {
		t.Fatalf("unmarshal sig: %v", err)
	}
	sig[0] ^= 0xFF
	raw["signature"], _ = json.Marshal(sig)
	desc, _ = json.Marshal(raw)

	if err := VerifyAdapterTrust(desc); err == nil {
		t.Fatal("expected bad-signature error")
	}
}

func TestVerifyPRCDeploymentByChain(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	pkPriv, _ := installTestChain(t)
	installDeploymentCert(t, pkPriv, "ethereum", "0xABCDEF")

	if err := VerifyPRCDeploymentByChain("ethereum", "0xABCDEF"); err != nil {
		t.Fatalf("VerifyPRCDeploymentByChain happy path: %v", err)
	}
	if err := VerifyPRCDeploymentByChain("ethereum", "0xwrong"); err == nil {
		t.Fatal("expected mismatch error")
	}
	if err := VerifyPRCDeploymentByChain("unknown", "0xABCDEF"); err == nil {
		t.Fatal("expected unknown-chain error")
	}
}

// TestComputeCanonicalPRCAddress_EIP1014Vector asserts that the low-level
// CREATE2 formula implemented by ComputeCanonicalPRCAddress agrees with the
// EIP-1014 reference vector. The canonical spec vector uses factory=0,
// salt=0, init_code=0x00 → 0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38. We
// reimplement that formula here (since our production helper is hard-wired
// to the Safe Singleton Factory and Plutus salt) to prove the keccak wiring
// matches Solidity's behaviour.
func TestComputeCanonicalPRCAddress_EIP1014Vector(t *testing.T) {
	factory := make([]byte, 20) // all zeros
	salt := make([]byte, 32)    // all zeros
	initCodeHash := keccak256([]byte{0x00})

	digest := keccak256(
		[]byte{0xff},
		factory,
		salt,
		initCodeHash,
	)
	got := "0x" + hex.EncodeToString(digest[12:])
	want := "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"
	if !strings.EqualFold(got, want) {
		t.Fatalf("EIP-1014 vector mismatch: got %s want %s", got, want)
	}
}

// TestComputeCanonicalPRCAddress_MatchesSolidityFormula verifies that the Go
// helper produces the same address a naive reimplementation of the Solidity
// computeAddress() function would produce, for a known (salt, initCode) pair.
// This is the cross-check that the Go and Solidity sides of the CREATE2
// computation stay in lock-step.
func TestComputeCanonicalPRCAddress_MatchesSolidityFormula(t *testing.T) {
	// Sample initCode — deterministic but arbitrary. In production this
	// would be the full ProtocolRegistry creation bytecode + ABI-encoded
	// constructor args.
	sampleInitCode := []byte("plutus:prc:test-initcode:v1")
	initCodeHash32 := [32]byte{}
	copy(initCodeHash32[:], keccak256(sampleInitCode))

	// Reference: run the same formula by hand with explicit byte assembly.
	factoryBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(SafeSingletonFactory), "0x"))
	if err != nil {
		t.Fatalf("decode factory: %v", err)
	}
	salt := PlutusPRCSalt()
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte{0xff})
	h.Write(factoryBytes)
	h.Write(salt[:])
	h.Write(initCodeHash32[:])
	ref := "0x" + hex.EncodeToString(h.Sum(nil)[12:])

	got := ComputeCanonicalPRCAddress(initCodeHash32)
	if !strings.EqualFold(got, ref) {
		t.Fatalf("ComputeCanonicalPRCAddress %s != reference %s", got, ref)
	}
	if len(got) != 42 { // "0x" + 40 hex chars
		t.Errorf("address wrong length: %d (%s)", len(got), got)
	}
	t.Logf("predicted PRC address for sample init-code: %s", got)
}

func TestIsCanonicalPRCAddress(t *testing.T) {
	// CanonicalPRCAddress is a compile-time const; when unset (pre-ceremony)
	// the predicate must return false for every input.
	if CanonicalPRCAddress == "" {
		if IsCanonicalPRCAddress("0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7") {
			t.Fatal("IsCanonicalPRCAddress must return false when CanonicalPRCAddress is empty")
		}
		if IsCanonicalPRCAddress("") {
			t.Fatal("IsCanonicalPRCAddress must return false for empty input when unset")
		}
		return
	}
	// Once populated, must be case-insensitive and reject non-matches.
	if !IsCanonicalPRCAddress(strings.ToUpper(CanonicalPRCAddress)) {
		t.Error("case-insensitive uppercase compare should match")
	}
	if !IsCanonicalPRCAddress(strings.ToLower(CanonicalPRCAddress)) {
		t.Error("case-insensitive lowercase compare should match")
	}
	if IsCanonicalPRCAddress("0xdeadbeef") {
		t.Error("wrong address must not match canonical")
	}
}

// TestPlutusPRCSalt_IncludesMaintainerHash locks the salt formula to
// keccak256("plutus-v1-prc" || MaintainerPubKeyHash). Rotating the maintainer
// key (and therefore MaintainerPubKeyHash) MUST yield a different salt so
// that the canonical PRC address also changes. Changing this test value
// would invalidate every PRC deployment.
func TestPlutusPRCSalt_IncludesMaintainerHash(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	// Install a deterministic maintainer hash so the expected salt is stable.
	MaintainerPubKeyHash = bytes.Repeat([]byte{0xAB}, 32)

	// Re-assemble the expected salt using the stdlib keccak primitive directly.
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("plutus-v1-prc"))
	h.Write(MaintainerPubKeyHash)
	want := h.Sum(nil)

	got := PlutusPRCSalt()
	if !bytes.Equal(got[:], want) {
		t.Fatalf("PlutusPRCSalt has drifted from keccak256(\"plutus-v1-prc\" || MaintainerPubKeyHash)\n got:  %x\n want: %x", got[:], want)
	}
	if len(got) != 32 {
		t.Fatalf("PlutusPRCSalt must be 32 bytes, got %d", len(got))
	}
}

// TestPlutusPRCSalt_ChangesWithMaintainerHash proves that rotating the
// maintainer key changes the CREATE2 salt (and therefore the canonical PRC
// address). This is the property that forces clients to migrate on rotation.
func TestPlutusPRCSalt_ChangesWithMaintainerHash(t *testing.T) {
	saved := snapshot()
	defer saved.restore()

	MaintainerPubKeyHash = bytes.Repeat([]byte{0x01}, 32)
	saltA := PlutusPRCSalt()

	MaintainerPubKeyHash = bytes.Repeat([]byte{0x02}, 32)
	saltB := PlutusPRCSalt()

	if bytes.Equal(saltA[:], saltB[:]) {
		t.Fatal("PlutusPRCSalt did not change when MaintainerPubKeyHash changed — rotation would NOT force a new PRC address")
	}

	// Cross-check: recompute both salts with the stdlib primitive and confirm
	// the bytes match the function's output.
	for _, tc := range []struct {
		name string
		hash []byte
		got  [32]byte
	}{
		{"hashA", bytes.Repeat([]byte{0x01}, 32), saltA},
		{"hashB", bytes.Repeat([]byte{0x02}, 32), saltB},
	} {
		h := sha3.NewLegacyKeccak256()
		h.Write([]byte("plutus-v1-prc"))
		h.Write(tc.hash)
		want := h.Sum(nil)
		if !bytes.Equal(tc.got[:], want) {
			t.Errorf("%s: salt bytes %x != stdlib reference %x", tc.name, tc.got[:], want)
		}
	}
}

func TestComputePlatformCertPayload_Deterministic(t *testing.T) {
	pk := bytes.Repeat([]byte{0x01}, 32)
	or := bytes.Repeat([]byte{0x02}, 32)
	ts := time.Unix(1_700_000_000, 0)

	a := computePlatformCertPayload(pk, or, ts)
	b := computePlatformCertPayload(pk, or, ts)
	if !bytes.Equal(a, b) {
		t.Error("payload must be deterministic")
	}
}

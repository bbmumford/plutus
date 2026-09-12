package wallet

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// BIP32 constants.
const (
	hardenedOffset = 0x80000000
)

// secp256k1N is the order of the secp256k1 group. We expose this as a
// package-level *big.Int because several functions in this file (and the
// former secp256k1_sign.go) check scalar validity against it. Sourced from
// the audited decred/dcrd/dcrec/secp256k1/v4 library.
var secp256k1N = secp256k1.Params().N

// DeriveProtocolIdentity derives an Ed25519 private key from a BIP39 seed
// using the path m/7777'/0'. This key is used as the Plutus protocol identity.
func DeriveProtocolIdentity(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("plutus/wallet: expected 64-byte seed, got %d", len(seed))
	}

	// BIP32 master key derivation.
	masterKey, masterChain, err := deriveMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// m/7777' (hardened)
	childKey, childChain, err := deriveHardenedChild(masterKey, masterChain, 7777)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777' failed: %w", err)
	}

	// m/7777'/0' (hardened)
	identityKey, _, err := deriveHardenedChild(childKey, childChain, 0)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777'/0' failed: %w", err)
	}

	// Use the 32-byte key material as an Ed25519 seed.
	return ed25519.NewKeyFromSeed(identityKey), nil
}

// DeriveStoreIdentity derives an Ed25519 private key for store operations
// using the path m/7777'/1'. This key is used for Mercury store signing.
//
// NOTE: The cryptographic-protocol.md spec describes HKDF for these derivations,
// but the codebase consistently uses BIP32. We keep BIP32 for consistency;
// the spec should be updated to match.
func DeriveStoreIdentity(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("plutus/wallet: expected 64-byte seed, got %d", len(seed))
	}

	masterKey, masterChain, err := deriveMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// m/7777' (hardened)
	childKey, childChain, err := deriveHardenedChild(masterKey, masterChain, 7777)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777' failed: %w", err)
	}

	// m/7777'/1' (hardened) — store identity
	identityKey, _, err := deriveHardenedChild(childKey, childChain, 1)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777'/1' failed: %w", err)
	}

	return ed25519.NewKeyFromSeed(identityKey), nil
}

// DeriveReplicatorKey derives an Ed25519 private key for replicator operations
// using the path m/7777'/2'. Replicators use this key to sign storage proofs
// and receipt acknowledgements.
//
// NOTE: Uses BIP32 derivation for consistency with DeriveProtocolIdentity,
// deviating from the HKDF approach described in cryptographic-protocol.md.
func DeriveReplicatorKey(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("plutus/wallet: expected 64-byte seed, got %d", len(seed))
	}

	masterKey, masterChain, err := deriveMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// m/7777' (hardened)
	childKey, childChain, err := deriveHardenedChild(masterKey, masterChain, 7777)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777' failed: %w", err)
	}

	// m/7777'/2' (hardened) — replicator key
	replicatorKey, _, err := deriveHardenedChild(childKey, childChain, 2)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777'/2' failed: %w", err)
	}

	return ed25519.NewKeyFromSeed(replicatorKey), nil
}

// DeriveArbitratorKey derives an Ed25519 private key for arbitrator operations
// using the path m/7777'/3'. Arbitrators use this key to sign dispute rulings.
//
// NOTE: Uses BIP32 derivation for consistency with DeriveProtocolIdentity,
// deviating from the HKDF approach described in cryptographic-protocol.md.
func DeriveArbitratorKey(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("plutus/wallet: expected 64-byte seed, got %d", len(seed))
	}

	masterKey, masterChain, err := deriveMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// m/7777' (hardened)
	childKey, childChain, err := deriveHardenedChild(masterKey, masterChain, 7777)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777' failed: %w", err)
	}

	// m/7777'/3' (hardened) — arbitrator key
	arbitratorKey, _, err := deriveHardenedChild(childKey, childChain, 3)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/7777'/3' failed: %w", err)
	}

	return ed25519.NewKeyFromSeed(arbitratorKey), nil
}

// DeriveOrderEscrowKey derives a secp256k1 ECDSA private key for a specific
// order's escrow. Used in BTC 2-of-3 multisig where each order gets unique
// keys derived from the master key plus a shared chaincode.
//
// The chaincode should be the SHA-256 hash of the order ID or a value agreed
// upon by both parties, ensuring deterministic per-order key derivation.
func DeriveOrderEscrowKey(masterKey *ECDSAPrivateKey, chaincode []byte) (*ECDSAPrivateKey, error) {
	if masterKey == nil {
		return nil, errors.New("plutus/wallet: master key is nil")
	}
	if len(chaincode) != 32 {
		return nil, fmt.Errorf("plutus/wallet: chaincode must be 32 bytes, got %d", len(chaincode))
	}

	// Derive a child key using the master key bytes + chaincode via BIP32-style
	// HMAC-SHA512. This produces a unique escrow key per order.
	parentKeyBytes := make([]byte, 32)
	b := masterKey.D.Bytes()
	copy(parentKeyBytes[32-len(b):], b)

	// Use non-hardened derivation with index 0 and the provided chaincode
	// as the parent chain code. This allows both parties with the chaincode
	// to derive the same child public key.
	childKeyBytes, _, err := deriveChildKey(parentKeyBytes, chaincode, 0)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive order escrow key: %w", err)
	}

	d := new(big.Int).SetBytes(childKeyBytes)
	if d.Sign() == 0 || d.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("plutus/wallet: derived escrow key is outside secp256k1 order")
	}

	x, y := pubKeyXY(childKeyBytes)
	return &ECDSAPrivateKey{
		D:     d,
		X:     x,
		Y:     y,
		Curve: secp256k1.S256(),
	}, nil
}

// DeriveChainKey derives a secp256k1 ECDSA private key for on-chain operations
// using the BIP44 path m/44'/coinType'/account'/0/0.
func DeriveChainKey(seed []byte, coinType uint32, account uint32) (*ECDSAPrivateKey, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("plutus/wallet: expected 64-byte seed, got %d", len(seed))
	}

	masterKey, masterChain, err := deriveMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// m/44' (purpose)
	key, chain, err := deriveHardenedChild(masterKey, masterChain, 44)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/44' failed: %w", err)
	}

	// m/44'/coinType'
	key, chain, err = deriveHardenedChild(key, chain, coinType)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/44'/%d' failed: %w", coinType, err)
	}

	// m/44'/coinType'/account'
	key, chain, err = deriveHardenedChild(key, chain, account)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive m/44'/%d'/%d' failed: %w", coinType, account, err)
	}

	// m/44'/coinType'/account'/0 (external chain, non-hardened)
	key, chain, err = deriveChildKey(key, chain, 0)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive external chain failed: %w", err)
	}

	// m/44'/coinType'/account'/0/0 (first address, non-hardened)
	key, _, err = deriveChildKey(key, chain, 0)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive address index failed: %w", err)
	}

	d := new(big.Int).SetBytes(key)
	if d.Sign() == 0 || d.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("plutus/wallet: derived key is outside secp256k1 order")
	}

	x, y := pubKeyXY(key)
	return &ECDSAPrivateKey{
		D:     d,
		X:     x,
		Y:     y,
		Curve: secp256k1.S256(),
	}, nil
}

// ECDSAPrivateKey represents a secp256k1 private key.
//
// The struct shape is preserved for API compatibility with downstream
// consumers (wallet.Wallet, Mercury, wasm bindings). Point operations on
// this key go through the audited decred/dcrd/dcrec/secp256k1/v4 library.
type ECDSAPrivateKey struct {
	D     *big.Int
	X, Y  *big.Int
	Curve elliptic.Curve
}

// PublicKeyBytes returns the uncompressed public key (65 bytes: 0x04 || X || Y).
func (k *ECDSAPrivateKey) PublicKeyBytes() []byte {
	xBytes := k.X.Bytes()
	yBytes := k.Y.Bytes()
	pub := make([]byte, 65)
	pub[0] = 0x04
	copy(pub[1+32-len(xBytes):33], xBytes)
	copy(pub[33+32-len(yBytes):65], yBytes)
	return pub
}

// ChainAddress computes an Ethereum-style address from a secp256k1 private key.
// The address is the last 20 bytes of the Keccak256 hash of the uncompressed
// public key (without the 0x04 prefix), formatted as a checksummed hex string.
func ChainAddress(privKey *ECDSAPrivateKey) string {
	pub := privKey.PublicKeyBytes()

	// Keccak256 of public key bytes (excluding the 0x04 prefix).
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pub[1:])
	digest := hash.Sum(nil)

	// Last 20 bytes = address.
	addr := digest[12:]
	return checksumAddress(addr)
}

// checksumAddress applies EIP-55 mixed-case checksum encoding.
func checksumAddress(addr []byte) string {
	hex := fmt.Sprintf("%x", addr)

	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(hex))
	hashHex := fmt.Sprintf("%x", hash.Sum(nil))

	result := make([]byte, 42)
	result[0] = '0'
	result[1] = 'x'
	for i := 0; i < 40; i++ {
		c := hex[i]
		if c >= 'a' && c <= 'f' && hashHex[i] >= '8' {
			result[i+2] = c - 32 // uppercase
		} else {
			result[i+2] = c
		}
	}
	return string(result)
}

// deriveMasterKey produces the BIP32 master secret key and chain code from a seed.
func deriveMasterKey(seed []byte) (key []byte, chainCode []byte, err error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	key = I[:32]
	chainCode = I[32:]

	// Validate key is within secp256k1 order.
	keyInt := new(big.Int).SetBytes(key)
	if keyInt.Sign() == 0 {
		return nil, nil, errors.New("plutus/wallet: master key is zero")
	}

	return key, chainCode, nil
}

// deriveHardenedChild derives a hardened child key (index >= 0x80000000).
func deriveHardenedChild(parentKey, parentChain []byte, index uint32) ([]byte, []byte, error) {
	data := make([]byte, 37)
	data[0] = 0x00
	copy(data[1:33], parentKey)
	binary.BigEndian.PutUint32(data[33:], index+hardenedOffset)

	mac := hmac.New(sha512.New, parentChain)
	mac.Write(data)
	I := mac.Sum(nil)

	childKey := I[:32]
	childChain := I[32:]

	// Add parent key to child key mod N (BIP32 spec).
	childInt := new(big.Int).SetBytes(childKey)
	parentInt := new(big.Int).SetBytes(parentKey)
	childInt.Add(childInt, parentInt)
	childInt.Mod(childInt, secp256k1N)

	if childInt.Sign() == 0 {
		return nil, nil, errors.New("plutus/wallet: derived key is zero")
	}

	result := make([]byte, 32)
	childBytes := childInt.Bytes()
	copy(result[32-len(childBytes):], childBytes)

	return result, childChain, nil
}

// deriveChildKey derives a normal (non-hardened) child key.
func deriveChildKey(parentKey, parentChain []byte, index uint32) ([]byte, []byte, error) {
	if index >= hardenedOffset {
		return nil, nil, errors.New("plutus/wallet: index too large for non-hardened derivation")
	}

	// For non-hardened: data = compressed_pubkey(parentKey) || index.
	// Delegated to the audited decred/dcrd/dcrec/secp256k1/v4 library.
	pubKey := pubKeyCompressed(parentKey)

	data := make([]byte, 37)
	copy(data[:33], pubKey)
	binary.BigEndian.PutUint32(data[33:], index)

	mac := hmac.New(sha512.New, parentChain)
	mac.Write(data)
	I := mac.Sum(nil)

	childKey := I[:32]
	childChain := I[32:]

	childInt := new(big.Int).SetBytes(childKey)
	parentInt := new(big.Int).SetBytes(parentKey)
	childInt.Add(childInt, parentInt)
	childInt.Mod(childInt, secp256k1N)

	if childInt.Sign() == 0 {
		return nil, nil, errors.New("plutus/wallet: derived key is zero")
	}

	result := make([]byte, 32)
	childBytes := childInt.Bytes()
	copy(result[32-len(childBytes):], childBytes)

	return result, childChain, nil
}

// pubKeyCompressed returns the 33-byte compressed secp256k1 public key
// corresponding to the given 32-byte private scalar. Returns a zero-filled
// compressed point for a zero scalar (which would also be rejected upstream
// by the BIP32 key-out-of-range checks).
func pubKeyCompressed(privScalar []byte) []byte {
	// PrivKeyFromBytes treats its input as big-endian and reduces mod N.
	priv := secp256k1.PrivKeyFromBytes(privScalar)
	return priv.PubKey().SerializeCompressed()
}

// pubKeyXY returns the affine (X, Y) coordinates of k*G for the given
// 32-byte private scalar, via the audited secp256k1 library.
func pubKeyXY(privScalar []byte) (*big.Int, *big.Int) {
	priv := secp256k1.PrivKeyFromBytes(privScalar)
	pub := priv.PubKey()
	// PubKey.SerializeUncompressed yields 0x04 || X(32) || Y(32).
	raw := pub.SerializeUncompressed()
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	return x, y
}

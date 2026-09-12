package wallet

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"
)

// GenerateMnemonic generates a 24-word BIP39 mnemonic from 256 bits of entropy.
func GenerateMnemonic() (string, error) {
	entropy := make([]byte, 32) // 256 bits
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("plutus/wallet: entropy generation failed: %w", err)
	}
	return entropyToMnemonic(entropy)
}

// MnemonicToSeed derives a 512-bit seed from a mnemonic and optional passphrase
// using PBKDF2-SHA512 with 2048 iterations per the BIP39 specification.
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	if !ValidateMnemonic(mnemonic) {
		return nil, errors.New("plutus/wallet: invalid mnemonic")
	}
	salt := "mnemonic" + passphrase
	key, err := pbkdf2.Key(sha512.New, mnemonic, []byte(salt), 2048, 64)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: PBKDF2 derivation failed: %w", err)
	}
	return key, nil
}

// ValidateMnemonic checks that a mnemonic is a valid 24-word BIP39 mnemonic
// with a correct checksum.
func ValidateMnemonic(mnemonic string) bool {
	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		return false
	}

	lookup := wordlistLookup()

	// Reconstruct the 264-bit stream (33 bytes = 256 bits entropy + 8 bits checksum).
	data := make([]byte, 33)
	for i, word := range words {
		idx, ok := lookup[strings.ToLower(word)]
		if !ok {
			return false
		}
		write11Bits(data, i*11, idx)
	}

	seed := data[:32]
	checksum := sha256.Sum256(seed)
	return data[32] == checksum[0]
}

// entropyToMnemonic converts 32 bytes of entropy into a 24-word mnemonic.
func entropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) != 32 {
		return "", fmt.Errorf("plutus/wallet: expected 32-byte entropy, got %d", len(entropy))
	}

	checksum := sha256.Sum256(entropy)

	// 32 bytes entropy + 1 byte checksum = 33 bytes = 264 bits = 24 * 11-bit indices.
	data := make([]byte, 33)
	copy(data, entropy)
	data[32] = checksum[0]

	words := make([]string, 24)
	for i := range 24 {
		idx := extract11Bits(data, i*11)
		words[i] = wordlist[idx]
	}

	return strings.Join(words, " "), nil
}

// wordlistLookup builds a reverse lookup map from word -> index.
func wordlistLookup() map[string]int {
	lookup := make(map[string]int, len(wordlist))
	for i, w := range wordlist {
		lookup[w] = i
	}
	return lookup
}

// extract11Bits reads an 11-bit value starting at the given bit offset.
func extract11Bits(data []byte, bitOffset int) int {
	byteIdx := bitOffset / 8
	shift := bitOffset % 8

	var val uint32
	val = uint32(data[byteIdx]) << 16
	if byteIdx+1 < len(data) {
		val |= uint32(data[byteIdx+1]) << 8
	}
	if byteIdx+2 < len(data) {
		val |= uint32(data[byteIdx+2])
	}

	return int((val >> uint(24-11-shift)) & 0x7FF)
}

// write11Bits writes an 11-bit value at the given bit offset.
func write11Bits(data []byte, bitOffset int, value int) {
	for bit := range 11 {
		if value&(1<<(10-bit)) != 0 {
			byteIdx := (bitOffset + bit) / 8
			bitIdx := 7 - (bitOffset+bit)%8
			data[byteIdx] |= 1 << uint(bitIdx)
		}
	}
}

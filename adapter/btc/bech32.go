/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package btc

import (
	"errors"
	"fmt"
	"strings"
)

// Minimal BIP173/BIP350 bech32 / bech32m implementation used for decoding
// Bitcoin P2WPKH ("bc1q..." for v0 witness) and P2WSH addresses into their
// constituent witness program bytes. Pure Go, no external deps.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Reverse = func() [128]int8 {
	var r [128]int8
	for i := range r {
		r[i] = -1
	}
	for i := 0; i < len(bech32Charset); i++ {
		r[bech32Charset[i]] = int8(i)
	}
	return r
}()

const (
	bech32Const  = 1          // BIP173 (v0 segwit)
	bech32mConst = 0x2bc830a3 // BIP350 (v1+ segwit, taproot)
)

func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])&31)
	}
	return out
}

// DecodeBech32 parses a bech32 / bech32m string and returns the HRP and the
// 5-bit data values (including checksum). The caller is responsible for
// stripping the 6-byte checksum.
func DecodeBech32(s string) (string, []int, bool, error) {
	lower := strings.ToLower(s)
	upper := strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, false, errors.New("btc/bech32: mixed case not allowed")
	}
	s = lower

	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, false, errors.New("btc/bech32: invalid separator position")
	}
	hrp := s[:pos]
	data := make([]int, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		c := s[i]
		if c >= 128 || bech32Reverse[c] < 0 {
			return "", nil, false, fmt.Errorf("btc/bech32: invalid character %q", c)
		}
		data = append(data, int(bech32Reverse[c]))
	}

	poly := bech32Polymod(append(bech32HrpExpand(hrp), data...))
	switch poly {
	case bech32Const:
		return hrp, data[:len(data)-6], false, nil
	case bech32mConst:
		return hrp, data[:len(data)-6], true, nil
	default:
		return "", nil, false, errors.New("btc/bech32: invalid checksum")
	}
}

// convertBits regroups a slice of integers from `frombits`-sized chunks into
// `tobits`-sized chunks. Used to convert between bech32's 5-bit groups and
// the 8-bit witness program bytes.
func convertBits(data []int, frombits, tobits uint, pad bool) ([]byte, error) {
	acc := 0
	bits := uint(0)
	out := make([]byte, 0, (len(data)*int(frombits)+int(tobits)-1)/int(tobits))
	maxv := (1 << tobits) - 1
	maxAcc := (1 << (frombits + tobits - 1)) - 1
	for _, v := range data {
		if v < 0 || (v>>frombits) != 0 {
			return nil, fmt.Errorf("btc/bech32: invalid data value %d", v)
		}
		acc = ((acc << frombits) | v) & maxAcc
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(tobits-bits))&maxv))
		}
	} else if bits >= frombits || ((acc<<(tobits-bits))&maxv) != 0 {
		return nil, errors.New("btc/bech32: invalid padding")
	}
	return out, nil
}

// SegWitAddress represents a decoded segwit bech32 address.
type SegWitAddress struct {
	HRP     string // "bc" for mainnet, "tb" for testnet, "bcrt" for regtest
	Version byte   // 0 for P2WPKH/P2WSH, 1 for P2TR
	Program []byte // witness program (20 bytes for P2WPKH, 32 for P2WSH)
}

// DecodeSegWitAddress parses a segwit address. It enforces:
//   - v0 must use bech32 (BIP173)
//   - v1+ must use bech32m (BIP350)
//   - v0 program length must be 20 or 32 bytes
func DecodeSegWitAddress(addr string) (*SegWitAddress, error) {
	hrp, data, isBech32m, err := DecodeBech32(addr)
	if err != nil {
		return nil, err
	}
	if len(data) < 1 {
		return nil, errors.New("btc/bech32: empty data part")
	}
	version := data[0]
	if version > 16 {
		return nil, fmt.Errorf("btc/bech32: witness version %d out of range", version)
	}

	program, err := convertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("btc/bech32: %w", err)
	}
	if len(program) < 2 || len(program) > 40 {
		return nil, fmt.Errorf("btc/bech32: witness program length %d invalid", len(program))
	}
	if version == 0 {
		if len(program) != 20 && len(program) != 32 {
			return nil, fmt.Errorf("btc/bech32: v0 program length %d must be 20 or 32", len(program))
		}
		if isBech32m {
			return nil, errors.New("btc/bech32: v0 address must use bech32, not bech32m")
		}
	} else {
		if !isBech32m {
			return nil, errors.New("btc/bech32: v1+ address must use bech32m")
		}
	}

	return &SegWitAddress{
		HRP:     hrp,
		Version: byte(version),
		Program: program,
	}, nil
}

// PkScriptForAddress returns the scriptPubKey bytes for a segwit bech32 address.
// Format: <version opcode> <push length> <program>
//
//	OP_0 (0x00) for v0, OP_1..OP_16 (0x51..0x60) for v1..v16.
func PkScriptForAddress(addr string) ([]byte, error) {
	sw, err := DecodeSegWitAddress(addr)
	if err != nil {
		return nil, err
	}
	var versionOp byte
	if sw.Version == 0 {
		versionOp = 0x00 // OP_0
	} else {
		versionOp = 0x50 + sw.Version // OP_1 = 0x51, ..., OP_16 = 0x60
	}
	script := make([]byte, 0, 2+len(sw.Program))
	script = append(script, versionOp)
	script = append(script, byte(len(sw.Program)))
	script = append(script, sw.Program...)
	return script, nil
}

// EncodeBech32 produces a bech32 or bech32m string from an HRP and 5-bit data.
func EncodeBech32(hrp string, data []int, useBech32m bool) (string, error) {
	values := append(bech32HrpExpand(hrp), data...)
	// Append 6 zeroes for checksum slots.
	values = append(values, 0, 0, 0, 0, 0, 0)
	checksumConst := bech32Const
	if useBech32m {
		checksumConst = bech32mConst
	}
	poly := bech32Polymod(values) ^ checksumConst
	var out strings.Builder
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, d := range data {
		if d < 0 || d >= len(bech32Charset) {
			return "", fmt.Errorf("btc/bech32: data value %d out of range", d)
		}
		out.WriteByte(bech32Charset[d])
	}
	for i := 0; i < 6; i++ {
		c := (poly >> (5 * (5 - i))) & 31
		out.WriteByte(bech32Charset[c])
	}
	return out.String(), nil
}

// EncodeSegWitAddress produces a segwit bech32/bech32m address from HRP,
// version, and witness program bytes.
func EncodeSegWitAddress(hrp string, version byte, program []byte) (string, error) {
	if version > 16 {
		return "", fmt.Errorf("btc/bech32: witness version %d out of range", version)
	}
	converted, err := convertBits(bytesToInts(program), 8, 5, true)
	if err != nil {
		return "", err
	}
	data := make([]int, 0, 1+len(converted))
	data = append(data, int(version))
	for _, b := range converted {
		data = append(data, int(b))
	}
	return EncodeBech32(hrp, data, version > 0)
}

func bytesToInts(b []byte) []int {
	out := make([]int, len(b))
	for i, v := range b {
		out[i] = int(v)
	}
	return out
}

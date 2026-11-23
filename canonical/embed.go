/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package canonical

import (
	_ "embed"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Embedded maintainer ceremony artifacts. These files are produced by the
// maintainer key ceremony and committed alongside the canonical package so
// that every binary -- including WASM -- carries the trust anchors at
// compile time. Re-running the ceremony rewrites these files and the next
// build will pick them up.

//go:embed keys/offline-root.pub
var embeddedOfflineRootPubHex string

//go:embed keys/platform-key.pub
var embeddedPlatformKeyPubHex string

//go:embed keys/platform-cert.json
var embeddedPlatformCert []byte

//go:embed keys/maintainer-btc-addr.txt
var embeddedMaintainerBTCAddr string

// parseMaintainerBTCAddr extracts the first non-comment, non-blank line from
// the embedded maintainer BTC address file. Returns "" if the file contains
// only comments/blanks.
func parseMaintainerBTCAddr(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

func init() {
	orPub, err := hex.DecodeString(strings.TrimSpace(embeddedOfflineRootPubHex))
	if err != nil {
		panic(fmt.Errorf("canonical: invalid embedded offline-root.pub hex: %w", err))
	}
	if len(orPub) != ed25519.PublicKeySize {
		panic(fmt.Errorf("canonical: embedded offline-root.pub has wrong length %d", len(orPub)))
	}

	pkPub, err := hex.DecodeString(strings.TrimSpace(embeddedPlatformKeyPubHex))
	if err != nil {
		panic(fmt.Errorf("canonical: invalid embedded platform-key.pub hex: %w", err))
	}
	if len(pkPub) != ed25519.PublicKeySize {
		panic(fmt.Errorf("canonical: embedded platform-key.pub has wrong length %d", len(pkPub)))
	}

	TrustChain.OfflineRootPubKey = orPub
	TrustChain.PlatformCert = embeddedPlatformCert

	pkHash := sha256.Sum256(pkPub)
	MaintainerPubKeyHash = pkHash[:]

	MaintainerBTCAddress = parseMaintainerBTCAddr(embeddedMaintainerBTCAddr)

	// Populate the legacy per-chain PRC map from the single CREATE2 address.
	// All supported EVM chains resolve to the same deterministic address via
	// the Safe Singleton Factory. Callers that still dispatch on chainID read
	// from the map; everyone else should use CanonicalPRCAddress directly.
	if CanonicalPRCAddress != "" {
		for chainID := range PRC {
			PRC[chainID] = CanonicalPRCAddress
		}
	}
}

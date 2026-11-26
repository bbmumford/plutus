/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package main

import (
	"fmt"

	"github.com/bbmumford/plutus/maintainer"
)

// runCertifyPRC signs a PRC deployment certificate with the Platform Key.
//
// The positional argument (after --) is the chain ID. Example:
//
//	plutus-ceremony certify-prc polygon \
//	   --platform platform.key \
//	   --addr 0xABCDEF... \
//	   --tx   0x123456... \
//	   --block 12345
//
// RunCertifyPRC is the exported entry point used by tests.
func RunCertifyPRC(args []string) error { return runCertifyPRC(args) }

func runCertifyPRC(args []string) error {
	fs := newFlagSet("certify-prc", "Sign a PRC deployment certificate per chain")
	dir := fs.String("dir", defaultDirForHelp(), "ceremony working directory (override with --dir)")
	platformKey := fs.String("platform", "platform.key", "path to the encrypted Platform Key (relative to --dir)")
	chainID := fs.String("chain", "", "chain ID (e.g. polygon, base, arbitrum). Overrides positional arg if set.")
	addr := fs.String("addr", "", "canonical PRC contract address (0x...)")
	tx := fs.String("tx", "", "deployment transaction hash (0x...)")
	block := fs.Uint64("block", 0, "block number the PRC was deployed in")
	output := fs.String("output", "", "output filename (defaults to <chain>.cert)")
	passEnv := fs.String("passphrase-from-env", "", "read Platform Key passphrase from this env var instead of prompting (non-interactive)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	chain := *chainID
	if chain == "" && fs.NArg() > 0 {
		chain = fs.Arg(0)
	}
	if chain == "" {
		return fmt.Errorf("chain ID is required (pass as positional arg or --chain)")
	}
	if *addr == "" || *tx == "" || *block == 0 {
		return fmt.Errorf("--addr, --tx, and --block are all required")
	}

	workDir, err := ensureDir(*dir)
	if err != nil {
		return err
	}

	passphrase, used, err := lookupPassphraseFromEnv(*passEnv)
	if err != nil {
		return err
	}
	if !used {
		passphrase, err = readPassphrase("Enter passphrase for Platform Key: ")
		if err != nil {
			return err
		}
	}

	pkPath := resolvePath(workDir, *platformKey)
	outName := *output
	if outName == "" {
		outName = chain + ".cert"
	}
	outPath := resolvePath(workDir, outName)

	if err := maintainer.CertifyPRCDeployment(pkPath, passphrase, chain, *addr, *tx, *block, outPath); err != nil {
		return fmt.Errorf("certify-prc: %w", err)
	}

	successf("PRC deployment certificate written to %s", outPath)
	return nil
}

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package main

import (
	"fmt"

	"github.com/bbmumford/plutus/maintainer"
)

// RunGenerateRoot is the exported entry point used by tests. It mirrors
// runGenerateRoot but is reachable from external callers (e.g. the
// end-to-end test in this package) without relying on the process-wide
// os.Args dispatch in main.go.
func RunGenerateRoot(args []string) error { return runGenerateRoot(args) }

// runGenerateRoot generates the Offline Root keypair and writes the
// encrypted private key to <dir>/<output>.
func runGenerateRoot(args []string) error {
	fs := newFlagSet("generate-root", "Generate the air-gapped Offline Root keypair")
	dir := fs.String("dir", defaultDirForHelp(), "ceremony working directory (override with --dir)")
	output := fs.String("output", "root.json", "output filename for the encrypted Offline Root key")
	passEnv := fs.String("passphrase-from-env", "", "read passphrase from this env var instead of prompting (non-interactive)")
	if err := fs.Parse(args); err != nil {
		return err
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
		passphrase, err = confirmPassphrase("Enter new passphrase for Offline Root key")
		if err != nil {
			return err
		}
	}

	outPath := resolvePath(workDir, *output)
	if err := maintainer.CeremonyGenerateRoot(passphrase, outPath); err != nil {
		return fmt.Errorf("generate-root: %w", err)
	}

	successf("Offline Root key written to %s", outPath)
	return nil
}

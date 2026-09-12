/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package main

import (
	"fmt"

	"github.com/bbmumford/plutus/maintainer"
)

// RunSignPlatform is the exported entry point used by tests.
func RunSignPlatform(args []string) error { return runSignPlatform(args) }

// runSignPlatform generates a Platform Key and signs its certificate with
// the Offline Root.
//
// Two artifacts are written:
//   - <output>.cert  the JSON-encoded platform certificate (signed by OR)
//   - <output>.key   the encrypted platform private key
func runSignPlatform(args []string) error {
	fs := newFlagSet("sign-platform", "Generate a Platform Key and sign its certificate with the Offline Root")
	dir := fs.String("dir", defaultDirForHelp(), "ceremony working directory (override with --dir)")
	rootKey := fs.String("root", "root.json", "path to the Offline Root key file (relative to --dir)")
	output := fs.String("output", "platform", "output basename (produces <name>.cert + <name>.key)")
	passEnv := fs.String("passphrase-from-env", "", "read OR passphrase from this env var instead of prompting (non-interactive)")
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
		passphrase, err = readPassphrase("Enter passphrase for Offline Root key: ")
		if err != nil {
			return err
		}
	}

	rootPath := resolvePath(workDir, *rootKey)
	outBase := resolvePath(workDir, *output)

	if err := maintainer.CeremonySignPlatform(rootPath, passphrase, outBase); err != nil {
		return fmt.Errorf("sign-platform: %w", err)
	}

	successf("Platform certificate written to %s.cert", outBase)
	successf("Encrypted Platform key written to %s.key", outBase)
	return nil
}

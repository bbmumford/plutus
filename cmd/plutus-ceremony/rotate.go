/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bbmumford/plutus/maintainer"
)

// RunRotatePlatform is the exported entry point used by tests.
func RunRotatePlatform(args []string) error { return runRotatePlatform(args) }

// runRotatePlatform rotates the Platform Key by generating a new PK and
// having the Offline Root re-sign a fresh certificate. Old artifacts are
// preserved — the caller should update canonical/embed.go and redeploy.
//
// The command prompts for TWO passphrases:
//  1. The existing Offline Root passphrase (required to unlock the OR key).
//  2. A passphrase for the NEW Platform Key. If left empty at the prompt,
//     the OR passphrase is reused with a warning — distinct passphrases per
//     key reduce blast radius and are strongly recommended.
//
// Non-interactive callers may pass --passphrase-from-env=VAR (OR passphrase)
// and --new-passphrase-from-env=VAR (new PK passphrase). Omitting the
// new-passphrase env var in non-interactive mode reuses the OR passphrase.
func runRotatePlatform(args []string) error {
	fs := newFlagSet("rotate-platform", "Rotate the Platform Key with a fresh OR-signed certificate")
	dir := fs.String("dir", defaultDirForHelp(), "ceremony working directory (override with --dir)")
	rootKey := fs.String("root", "root.json", "path to the Offline Root key file (relative to --dir)")
	oldCert := fs.String("old-cert", "platform.cert", "current platform certificate (relative to --dir)")
	output := fs.String("output", "platform-new", "output basename for the new PK (<name>.cert + <name>.key)")
	passEnv := fs.String("passphrase-from-env", "", "read OR passphrase from this env var instead of prompting (non-interactive)")
	newPassEnv := fs.String("new-passphrase-from-env", "", "read NEW PK passphrase from this env var (empty = reuse OR passphrase)")
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
		passphrase, err = readPassphrase("Enter passphrase for existing Offline Root key: ")
		if err != nil {
			return err
		}
	}

	// Resolve the passphrase for the NEW Platform Key. Preference order:
	//   --new-passphrase-from-env → interactive prompt → reuse OR.
	newPKPass := passphrase
	newUsed := false
	if envVal, ok, err := lookupPassphraseFromEnv(*newPassEnv); err != nil {
		return err
	} else if ok {
		newPKPass = envVal
		newUsed = true
	}
	if !newUsed && *passEnv == "" {
		// Only prompt interactively when the OR passphrase itself was
		// collected interactively; otherwise we're in fully scripted mode
		// and a missing new-passphrase env var means "reuse OR".
		entered, err := readPassphrase("Enter passphrase for NEW Platform Key (leave empty to reuse OR passphrase): ")
		if err != nil {
			// Empty passphrase is a signal to reuse OR — downgrade the
			// "passphrase is empty" error into the reuse path.
			if err.Error() == "passphrase is empty" {
				fmt.Fprintln(os.Stderr, "warning: reusing OR passphrase for new PK — consider a distinct passphrase for better compartmentalisation")
			} else {
				return err
			}
		} else {
			confirm, err := readPassphrase("Confirm NEW Platform Key passphrase: ")
			if err != nil {
				return err
			}
			if entered != confirm {
				return fmt.Errorf("new platform key passphrases do not match")
			}
			newPKPass = entered
		}
	} else if !newUsed {
		// OR came from env but new-passphrase env var not supplied: silently reuse.
		fmt.Fprintln(os.Stderr, "warning: reusing OR passphrase for new PK — consider a distinct passphrase for better compartmentalisation")
	}

	// Decrypt Offline Root.
	rootPath := resolvePath(workDir, *rootKey)
	rootData, err := os.ReadFile(rootPath)
	if err != nil {
		return fmt.Errorf("read root key: %w", err)
	}
	var rootFile struct {
		PublicKey           string `json:"publicKey"`
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	}
	if err := json.Unmarshal(rootData, &rootFile); err != nil {
		return fmt.Errorf("parse root key: %w", err)
	}
	pub, err := hex.DecodeString(rootFile.PublicKey)
	if err != nil {
		return fmt.Errorf("decode root public key: %w", err)
	}
	encPriv, err := hex.DecodeString(rootFile.EncryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("decode root encrypted private key: %w", err)
	}
	offlineRoot, err := maintainer.DecryptOfflineRoot(ed25519.PublicKey(pub), encPriv, passphrase)
	if err != nil {
		return fmt.Errorf("decrypt offline root: %w", err)
	}

	// Load old platform certificate for audit trail.
	oldCertPath := resolvePath(workDir, *oldCert)
	old, err := maintainer.LoadPlatformCert(oldCertPath)
	if err != nil {
		return fmt.Errorf("load old platform cert: %w", err)
	}

	// Rotate.
	result, err := maintainer.RotatePlatformKey(offlineRoot, old)
	if err != nil {
		return fmt.Errorf("rotate platform key: %w", err)
	}

	// Write new cert + encrypted private key.
	newBase := resolvePath(workDir, *output)
	newCertPath := newBase + ".cert"
	if err := maintainer.SavePlatformCert(newCertPath, result.NewCert); err != nil {
		return fmt.Errorf("save new cert: %w", err)
	}

	// Persist the new private key using the keygen encryption format so the
	// maintainer.CertifyPRCDeployment flow can re-use it directly.
	newKey := &maintainer.MaintainerKey{
		PublicKey:    result.NewCert.PlatformPubKey,
		PublicKeyHex: hex.EncodeToString(result.NewCert.PlatformPubKey),
	}
	newKeyPath := newBase + ".key"
	if err := maintainer.SaveKey(newKeyPath, newKey, result.NewPrivateKey, newPKPass); err != nil {
		return fmt.Errorf("save new platform key: %w", err)
	}

	successf("New platform certificate written to %s", newCertPath)
	successf("New encrypted platform key written to %s", newKeyPath)
	fmt.Fprintln(os.Stdout, "Reminder: update canonical/embed.go and redeploy the PRC contracts.")
	return nil
}

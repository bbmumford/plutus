/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package main

import (
	"fmt"
	"path/filepath"

	"github.com/bbmumford/plutus/maintainer"
)

// RunEmitCanonical is the exported entry point used by tests.
func RunEmitCanonical(args []string) error { return runEmitCanonical(args) }

// runEmitCanonical prints the Go source snippet that can be pasted into
// canonical/embed.go. Collects the Offline Root public key, the Platform
// certificate, and one or more PRC deployment certs.
func runEmitCanonical(args []string) error {
	fs := newFlagSet("emit-canonical", "Print the canonical/embed.go snippet from ceremony artifacts")
	dir := fs.String("dir", defaultDirForHelp(), "ceremony working directory (override with --dir)")
	rootKey := fs.String("root", "root.json", "Offline Root key file (public key is read from here)")
	platformCert := fs.String("platform-cert", "platform.cert", "Platform certificate file")
	deployCerts := fs.String("deploy-certs", "", "comma-separated list of per-chain deployment cert files")
	deployGlob := fs.String("deploy-glob", "", "optional glob (e.g. '*.cert') resolved relative to --dir if --deploy-certs is empty")
	if err := fs.Parse(args); err != nil {
		return err
	}

	workDir, err := ensureDir(*dir)
	if err != nil {
		return err
	}

	rootPath := resolvePath(workDir, *rootKey)
	platformPath := resolvePath(workDir, *platformCert)

	var certPaths []string
	for _, p := range splitCSV(*deployCerts) {
		certPaths = append(certPaths, resolvePath(workDir, p))
	}
	if len(certPaths) == 0 && *deployGlob != "" {
		matches, err := filepath.Glob(resolvePath(workDir, *deployGlob))
		if err != nil {
			return fmt.Errorf("deploy-glob: %w", err)
		}
		// Filter out the platform cert itself from the glob results.
		for _, m := range matches {
			if m == platformPath {
				continue
			}
			certPaths = append(certPaths, m)
		}
	}
	if len(certPaths) == 0 {
		return fmt.Errorf("at least one deployment cert must be provided (--deploy-certs or --deploy-glob)")
	}

	if err := maintainer.EmitCanonicalSource(rootPath, platformPath, certPaths); err != nil {
		return fmt.Errorf("emit-canonical: %w", err)
	}

	return nil
}

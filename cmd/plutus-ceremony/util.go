/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

// defaultDir returns the default ceremony working directory
// (~/.plutus by default) unless overridden by --dir. It is created with
// 0700 permissions if it does not yet exist.
//
// If the home directory cannot be determined (e.g. in a minimal
// environment with no HOME/USERPROFILE set), we fall back to a relative
// path so the tool still runs. Callers can always override via --dir.
func defaultDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".plutus")
	}
	return filepath.Join(".", "plutus-ceremony")
}

// defaultDirForHelp returns defaultDir() with path separators normalised
// to forward slashes. It is used purely for --help rendering so that the
// path reads cleanly in terminals on Windows where backslashes look like
// escape sequences. The runtime default still uses filepath.Join so real
// filesystem operations get the native separator.
func defaultDirForHelp() string {
	return filepath.ToSlash(defaultDir())
}

// lookupPassphraseFromEnv resolves a --passphrase-from-env flag value to
// the passphrase stored in that environment variable. An empty name means
// the flag was not supplied; an empty or unset value is a hard error
// (no silent fallback to interactive prompting).
func lookupPassphraseFromEnv(varName string) (string, bool, error) {
	if varName == "" {
		return "", false, nil
	}
	val, ok := os.LookupEnv(varName)
	if !ok {
		return "", true, fmt.Errorf("env var %s is not set", varName)
	}
	if val == "" {
		return "", true, fmt.Errorf("env var %s is empty", varName)
	}
	return val, true, nil
}

// ensureDir creates dir with 0700 permissions if absent. Returns the
// absolute path on success.
func ensureDir(dir string) (string, error) {
	if dir == "" {
		dir = defaultDir()
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve dir: %w", err)
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return "", fmt.Errorf("create dir %s: %w", abs, err)
	}
	return abs, nil
}

// readPassphrase prompts the user and reads a passphrase from stdin with
// terminal echo disabled. If stdin is not a terminal (e.g. piped input),
// the first non-empty line is read instead.
func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		pp := strings.TrimSpace(string(pw))
		if pp == "" {
			return "", fmt.Errorf("passphrase is empty")
		}
		return pp, nil
	}

	// Non-interactive: read a line.
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", fmt.Errorf("read passphrase: no input")
	}
	pp := strings.TrimSpace(scanner.Text())
	if pp == "" {
		return "", fmt.Errorf("passphrase is empty")
	}
	return pp, nil
}

// confirmPassphrase prompts twice and ensures both entries match. Used when
// generating new keys to guard against typos.
func confirmPassphrase(prompt string) (string, error) {
	first, err := readPassphrase(prompt + ": ")
	if err != nil {
		return "", err
	}
	second, err := readPassphrase("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passphrases do not match")
	}
	return first, nil
}

// resolvePath resolves a user-provided file path relative to the ceremony
// directory if the path is not already absolute.
func resolvePath(dir, p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// successf prints a success line prefixed with a check glyph.
func successf(format string, args ...interface{}) {
	fmt.Printf("OK: "+format+"\n", args...)
}

// splitCSV returns the non-empty whitespace-trimmed comma-separated values.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

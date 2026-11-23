/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCeremonyE2E drives the plutus-ceremony CLI through a full
// generate-root → sign-platform → certify-prc → verify → emit-canonical →
// rotate-platform → verify-rotated flow against a temp directory.
//
// The test calls each subcommand's exported entry point directly, using
// the --passphrase-from-env flag to feed passphrases without touching the
// terminal. Subtests allow each stage to be debugged independently via
// `go test -run TestCeremonyE2E/sign-platform` etc.
func TestCeremonyE2E(t *testing.T) {
	dir := t.TempDir()

	const (
		orEnv     = "OR_PASS_E2E"
		pkEnv     = "PK_PASS_E2E"
		newPKEnv  = "NEW_PK_PASS_E2E"
		orPass    = "correct-horse-battery-staple"
		pkPass    = "another-strong-passphrase"
		newPkPass = "third-passphrase-for-rotation"
	)

	t.Setenv(orEnv, orPass)
	t.Setenv(pkEnv, pkPass)
	t.Setenv(newPKEnv, newPkPass)

	t.Run("generate-root", func(t *testing.T) {
		if err := RunGenerateRoot([]string{
			"--dir", dir,
			"--output", "root.json",
			"--passphrase-from-env", orEnv,
		}); err != nil {
			t.Fatalf("RunGenerateRoot: %v", err)
		}
		mustExist(t, filepath.Join(dir, "root.json"))
	})

	t.Run("sign-platform", func(t *testing.T) {
		// sign-platform's OR passphrase is the OR key's passphrase; the
		// underlying maintainer API reuses it to encrypt the new PK too.
		if err := RunSignPlatform([]string{
			"--dir", dir,
			"--root", "root.json",
			"--output", "platform",
			"--passphrase-from-env", orEnv,
		}); err != nil {
			t.Fatalf("RunSignPlatform: %v", err)
		}
		mustExist(t, filepath.Join(dir, "platform.cert"))
		mustExist(t, filepath.Join(dir, "platform.key"))
	})

	t.Run("certify-prc", func(t *testing.T) {
		// The PK file was encrypted by sign-platform using the OR
		// passphrase (that's how the current maintainer API works), so we
		// pass the OR env var as the unlock secret here.
		if err := RunCertifyPRC([]string{
			"--dir", dir,
			"--platform", "platform.key",
			"--chain", "polygon",
			"--addr", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"--tx", "0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
			"--block", "12345",
			"--output", "polygon.cert",
			"--passphrase-from-env", orEnv,
		}); err != nil {
			t.Fatalf("RunCertifyPRC: %v", err)
		}
		mustExist(t, filepath.Join(dir, "polygon.cert"))
	})

	t.Run("verify-all", func(t *testing.T) {
		for _, f := range []string{"root.json", "platform.cert", "platform.key", "polygon.cert"} {
			if err := RunVerify([]string{"--dir", dir, f}); err != nil {
				t.Errorf("RunVerify(%s): %v", f, err)
			}
		}
	})

	t.Run("emit-canonical", func(t *testing.T) {
		out := captureStdout(t, func() {
			if err := RunEmitCanonical([]string{
				"--dir", dir,
				"--root", "root.json",
				"--platform-cert", "platform.cert",
				"--deploy-certs", "polygon.cert",
			}); err != nil {
				t.Fatalf("RunEmitCanonical: %v", err)
			}
		})

		if !strings.Contains(out, "OfflineRootPubKey:") {
			t.Errorf("emit-canonical output missing OfflineRootPubKey marker; got:\n%s", out)
		}
		if !strings.Contains(out, "PlatformCert:") {
			t.Errorf("emit-canonical output missing PlatformCert marker; got:\n%s", out)
		}

		// The emitted snippet is two concatenated fragments: a block of
		// struct-literal fields (OfflineRootPubKey / PlatformCert / …)
		// followed by a top-level `var CanonicalMaintainerPubKeyHash`
		// declaration. Split on the known marker comment and validate
		// each fragment parses in an appropriate host context.
		const splitMarker = "// MaintainerPubKeyHash"
		idx := strings.Index(out, splitMarker)
		if idx < 0 {
			t.Fatalf("emit-canonical output missing %q marker; got:\n%s", splitMarker, out)
		}
		structPart := out[:idx]
		varPart := out[idx:]

		fset := token.NewFileSet()
		wrappedStruct := "package p\ntype Embed struct {\n" +
			"\tOfflineRootPubKey []byte\n" +
			"\tPlatformCert []byte\n" +
			"\tPRCDeployments map[string][]byte\n" +
			"\tCheckpoints map[string]string\n" +
			"}\n" +
			"var _ = Embed{\n" + structPart + "\n}\n"
		if _, err := parser.ParseFile(fset, "embed_struct.go", wrappedStruct, parser.AllErrors); err != nil {
			t.Errorf("struct-literal fragment failed to parse: %v\nfragment:\n%s", err, structPart)
		}

		wrappedVar := "package p\n" + varPart
		if _, err := parser.ParseFile(fset, "embed_var.go", wrappedVar, parser.AllErrors); err != nil {
			t.Errorf("var-declaration fragment failed to parse: %v\nfragment:\n%s", err, varPart)
		}
	})

	t.Run("rotate-platform", func(t *testing.T) {
		if err := RunRotatePlatform([]string{
			"--dir", dir,
			"--root", "root.json",
			"--old-cert", "platform.cert",
			"--output", "platform-new",
			"--passphrase-from-env", orEnv,
			"--new-passphrase-from-env", newPKEnv,
		}); err != nil {
			t.Fatalf("RunRotatePlatform: %v", err)
		}
		mustExist(t, filepath.Join(dir, "platform-new.cert"))
		mustExist(t, filepath.Join(dir, "platform-new.key"))
	})

	t.Run("verify-rotated", func(t *testing.T) {
		for _, f := range []string{"platform-new.cert", "platform-new.key"} {
			if err := RunVerify([]string{"--dir", dir, f}); err != nil {
				t.Errorf("RunVerify(%s): %v", f, err)
			}
		}
	})

	// t.TempDir() guarantees cleanup on test completion; the presence check
	// below merely documents the directory still exists during the test so
	// its disappearance afterwards is attributable to the harness.
	t.Run("tempdir-present-during-test", func(t *testing.T) {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("temp dir vanished prematurely: %v", err)
		}
	})
}

// TestDefaultDirForHelp exercises the Windows forward-slash rendering of
// the --help default. We can't change runtime GOOS, but we can assert that
// the help variant contains no backslashes regardless of platform.
func TestDefaultDirForHelp(t *testing.T) {
	got := defaultDirForHelp()
	if strings.Contains(got, "\\") {
		t.Errorf("defaultDirForHelp() must not contain backslashes; got %q", got)
	}
	if got == "" {
		t.Errorf("defaultDirForHelp() must not be empty")
	}
}

// TestLookupPassphraseFromEnv covers the three branches of the env-var
// passphrase resolver: unset name (no-op), empty value (error), unset value
// (error), set value (returned).
func TestLookupPassphraseFromEnv(t *testing.T) {
	// Unset name → no-op.
	if v, used, err := lookupPassphraseFromEnv(""); err != nil || used || v != "" {
		t.Errorf("empty name: got v=%q used=%v err=%v", v, used, err)
	}

	// Unset env var → error.
	const missingVar = "PLUTUS_CEREMONY_TEST_MISSING_VAR"
	os.Unsetenv(missingVar)
	if _, used, err := lookupPassphraseFromEnv(missingVar); err == nil || !used {
		t.Errorf("missing env var should error; used=%v err=%v", used, err)
	}

	// Empty env var → error.
	t.Setenv("PLUTUS_CEREMONY_TEST_EMPTY_VAR", "")
	if _, used, err := lookupPassphraseFromEnv("PLUTUS_CEREMONY_TEST_EMPTY_VAR"); err == nil || !used {
		t.Errorf("empty env var should error; used=%v err=%v", used, err)
	}

	// Set env var → returned.
	t.Setenv("PLUTUS_CEREMONY_TEST_SET_VAR", "secret")
	v, used, err := lookupPassphraseFromEnv("PLUTUS_CEREMONY_TEST_SET_VAR")
	if err != nil || !used || v != "secret" {
		t.Errorf("set env var: got v=%q used=%v err=%v", v, used, err)
	}
}

// mustExist fails the test if path does not refer to a regular file.
func mustExist(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
	if info.IsDir() {
		t.Fatalf("expected %s to be a file, got directory", path)
	}
	if info.Size() == 0 {
		t.Fatalf("expected %s to be non-empty", path)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. Used to capture emit-canonical's output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.Bytes()
	}()

	fn()

	_ = w.Close()
	os.Stdout = orig
	return string(<-done)
}

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// helper: make a path inside t.TempDir (auto-cleaned).
func tmpKeyfile(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestEncryptedKeyfile_RoundTrip(t *testing.T) {
	path := tmpKeyfile(t, "wallet.key")
	plaintext := []byte("super-secret-private-key-material")
	pass := []byte("correct horse battery staple")

	if err := WriteEncryptedKeyfile(path, pass, plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := ReadEncryptedKeyfile(path, pass)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch:\n got=%q\nwant=%q", got, plaintext)
	}
}

func TestEncryptedKeyfile_WrongPassphrase(t *testing.T) {
	path := tmpKeyfile(t, "wallet.key")
	if err := WriteEncryptedKeyfile(path, []byte("right"), []byte("payload")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	_, err := ReadEncryptedKeyfile(path, []byte("wrong"))
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}
}

func TestEncryptedKeyfile_NotFound(t *testing.T) {
	path := tmpKeyfile(t, "does-not-exist.key")
	_, err := ReadEncryptedKeyfile(path, []byte("x"))
	if !errors.Is(err, ErrKeyfileNotFound) {
		t.Fatalf("expected ErrKeyfileNotFound, got %v", err)
	}
}

func TestEncryptedKeyfile_TruncatedCorrupt(t *testing.T) {
	// Any file shorter than salt+nonce+tag must be rejected as corrupt.
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"salt_only", saltSize},
		{"salt_plus_nonce", saltSize + nonceSize},
		{"salt_nonce_partial_tag", saltSize + nonceSize + tagSize - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tmpKeyfile(t, "trunc.key")
			buf := make([]byte, tc.size)
			// Fill with non-zero so a bug that only checks for empty would pass
			// but this test still catches it.
			for i := range buf {
				buf[i] = 0xAB
			}
			if err := os.WriteFile(path, buf, 0o600); err != nil {
				t.Fatalf("setup: %v", err)
			}
			_, err := ReadEncryptedKeyfile(path, []byte("whatever"))
			if !errors.Is(err, ErrKeyfileCorrupt) {
				t.Fatalf("expected ErrKeyfileCorrupt for size %d, got %v", tc.size, err)
			}
		})
	}
}

func TestEncryptedKeyfile_TamperedCiphertext(t *testing.T) {
	path := tmpKeyfile(t, "wallet.key")
	pass := []byte("pw")
	if err := WriteEncryptedKeyfile(path, pass, []byte("hello world, payload")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read-back: %v", err)
	}

	// Flip one bit in the middle of the ciphertext — AEAD must reject.
	tamperOffset := saltSize + nonceSize + 2
	if tamperOffset >= len(data) {
		t.Fatalf("file too short to tamper: %d", len(data))
	}
	data[tamperOffset] ^= 0x01
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}

	_, err = ReadEncryptedKeyfile(path, pass)
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase after tamper, got %v", err)
	}
}

func TestEncryptedKeyfile_TamperedTag(t *testing.T) {
	// Flipping a bit inside the Poly1305 tag (last 16 bytes) must also fail.
	path := tmpKeyfile(t, "wallet.key")
	pass := []byte("pw")
	if err := WriteEncryptedKeyfile(path, pass, []byte("payload")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read-back: %v", err)
	}
	data[len(data)-1] ^= 0x80
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	_, err = ReadEncryptedKeyfile(path, pass)
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase after tag flip, got %v", err)
	}
}

func TestEncryptedKeyfile_Rewrap(t *testing.T) {
	path := tmpKeyfile(t, "wallet.key")
	payload := []byte("witness-payout-btc-priv")
	oldPW := []byte("old-pw")
	newPW := []byte("new-pw")

	if err := WriteEncryptedKeyfile(path, oldPW, payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Capture salt+nonce before rewrap so we can assert fresh randomness.
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read-before: %v", err)
	}

	if err := RewrapKeyfile(path, oldPW, newPW); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read-after: %v", err)
	}

	// Old passphrase must no longer decrypt.
	if _, err := ReadEncryptedKeyfile(path, oldPW); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase on old pw post-rewrap, got %v", err)
	}

	// New passphrase must decrypt and yield the original plaintext.
	got, err := ReadEncryptedKeyfile(path, newPW)
	if err != nil {
		t.Fatalf("Read(new): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("post-rewrap plaintext mismatch:\n got=%q\nwant=%q", got, payload)
	}

	// Salt + nonce should differ — rewrap MUST generate fresh randomness.
	if bytes.Equal(before[:saltSize], after[:saltSize]) {
		t.Errorf("rewrap reused salt")
	}
	if bytes.Equal(before[saltSize:saltSize+nonceSize], after[saltSize:saltSize+nonceSize]) {
		t.Errorf("rewrap reused nonce")
	}
}

func TestEncryptedKeyfile_Rewrap_WrongOldPW(t *testing.T) {
	path := tmpKeyfile(t, "wallet.key")
	if err := WriteEncryptedKeyfile(path, []byte("old"), []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	err := RewrapKeyfile(path, []byte("nope"), []byte("new"))
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}

	// File must be unchanged — old passphrase still works.
	got, err := ReadEncryptedKeyfile(path, []byte("old"))
	if err != nil {
		t.Fatalf("Read(old) after failed rewrap: %v", err)
	}
	if !bytes.Equal(got, []byte("x")) {
		t.Fatalf("rewrap-failure corrupted file")
	}
}

func TestEncryptedKeyfile_Permissions0600(t *testing.T) {
	// File mode bits are not meaningful on Windows in the same way.
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits not enforced on windows")
	}
	path := tmpKeyfile(t, "wallet.key")
	if err := WriteEncryptedKeyfile(path, []byte("pw"), []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Fatalf("expected mode 0600, got %o", perm)
	}
}

func TestEncryptedKeyfile_RefuseOverwrite(t *testing.T) {
	path := tmpKeyfile(t, "wallet.key")
	if err := WriteEncryptedKeyfile(path, []byte("pw"), []byte("first")); err != nil {
		t.Fatalf("Write#1: %v", err)
	}
	err := WriteEncryptedKeyfile(path, []byte("pw"), []byte("second"))
	if !errors.Is(err, ErrKeyfileExists) {
		t.Fatalf("expected ErrKeyfileExists, got %v", err)
	}

	// First file must still be intact.
	got, err := ReadEncryptedKeyfile(path, []byte("pw"))
	if err != nil {
		t.Fatalf("Read after refused overwrite: %v", err)
	}
	if !bytes.Equal(got, []byte("first")) {
		t.Fatalf("refused-overwrite clobbered the original: %q", got)
	}
}

func TestEncryptedKeyfile_EmptyPassphrase(t *testing.T) {
	// Per spec: empty passphrase is ALLOWED (unencrypted-in-spirit, but still
	// runs Argon2id + AEAD so the format is uniform).
	path := tmpKeyfile(t, "wallet.key")
	payload := []byte("plaintext-ish")
	if err := WriteEncryptedKeyfile(path, nil, payload); err != nil {
		t.Fatalf("Write(empty): %v", err)
	}
	got, err := ReadEncryptedKeyfile(path, nil)
	if err != nil {
		t.Fatalf("Read(empty): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("empty-passphrase round-trip mismatch")
	}

	// A non-empty passphrase must still be rejected — empty is distinct from "any".
	if _, err := ReadEncryptedKeyfile(path, []byte("x")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase with wrong pw against empty-pw file, got %v", err)
	}
}

func TestEncryptedKeyfile_ConcurrentWritesDifferentPaths(t *testing.T) {
	// Argon2 is memory-hungry so keep the fan-out modest.
	const workers = 4
	dir := t.TempDir()
	pass := []byte("pw")

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := filepath.Join(dir, fmt.Sprintf("w-%d.key", i))
			payload := []byte(fmt.Sprintf("payload-%d", i))
			if err := WriteEncryptedKeyfile(path, pass, payload); err != nil {
				errs <- fmt.Errorf("worker %d write: %w", i, err)
				return
			}
			got, err := ReadEncryptedKeyfile(path, pass)
			if err != nil {
				errs <- fmt.Errorf("worker %d read: %w", i, err)
				return
			}
			if !bytes.Equal(got, payload) {
				errs <- fmt.Errorf("worker %d mismatch: got=%q want=%q", i, got, payload)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestEncryptedKeyfile_WireFormat(t *testing.T) {
	// Belt-and-braces check: the on-disk layout must be [salt:16][nonce:24][ct+tag],
	// where len(ct+tag) == len(plaintext)+16. This pins the spec into the tests.
	path := tmpKeyfile(t, "wallet.key")
	payload := []byte("12345") // 5 bytes
	if err := WriteEncryptedKeyfile(path, []byte("pw"), payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read-back: %v", err)
	}
	wantLen := saltSize + nonceSize + len(payload) + tagSize
	if len(data) != wantLen {
		t.Fatalf("file size = %d, want %d (salt+nonce+pt+tag)", len(data), wantLen)
	}
}

func TestPassphraseFromEnv(t *testing.T) {
	t.Setenv("PLUTUS_TEST_PASS", "hello \t\r\n")
	got, err := PassphraseFromEnv("PLUTUS_TEST_PASS")
	if err != nil {
		t.Fatalf("PassphraseFromEnv: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("trimming failed: got %q", got)
	}

	// Empty var name is rejected.
	if _, err := PassphraseFromEnv(""); err == nil {
		t.Fatal("expected error for empty env name")
	}

	// Unset var returns empty, no error.
	t.Setenv("PLUTUS_TEST_UNSET", "")
	got2, err := PassphraseFromEnv("PLUTUS_TEST_UNSET")
	if err != nil {
		t.Fatalf("unset: %v", err)
	}
	if len(got2) != 0 {
		t.Fatalf("expected empty, got %q", got2)
	}
}

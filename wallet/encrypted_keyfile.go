/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package wallet

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

// Encrypted-keyfile primitive for on-disk storage of wallet private keys
// (including witness payout-wallet keys used by the fee distributor's signer).
//
// Format (witness.readEncryptedKeyfile reads the same bytes):
//
//   [salt:16][nonce:24][ciphertext][tag:16]
//
// Where:
//   - salt: 16 random bytes, input to Argon2id
//   - nonce: 24 random bytes for XChaCha20-Poly1305
//   - ciphertext: plaintext encrypted with the Argon2id-derived key
//   - tag: 16-byte Poly1305 authenticator (appended to ciphertext by aead.Seal)
//
// Associated data is the constant string keyfileAD ("mercury-wallet-v1"). The
// empty passphrase is intentionally allowed (it means no passphrase) but still
// runs the full Argon2id + AEAD path so the on-disk format is uniform —
// callers never have to special-case an unencrypted blob.
//
// NOTE on format versioning: the blob carries no format version byte; it is
// exactly [salt:16][nonce:24][ciphertext][tag:16], which
// witness.readEncryptedKeyfile also parses. Changing the KDF parameters or the
// layout changes the format both readers share, so they change together.

// keyfileAD is the Associated Data bound into every wallet keyfile. Changing
// this string renders all existing files unreadable (AEAD verify will fail
// with ErrBadPassphrase).
const keyfileAD = "mercury-wallet-v1"

// Argon2id + XChaCha20-Poly1305 parameters of the keyfile format.
const (
	argon2TimeV1    = 3
	argon2MemoryV1  = 64 * 1024 // 64 MB
	argon2ThreadsV1 = 4
	argon2KeyLenV1  = 32
	saltSize        = 16
	nonceSize       = 24 // XChaCha20-Poly1305 nonce (chacha20poly1305.NonceSizeX)
	tagSize         = 16 // Poly1305 tag (chacha20poly1305.Overhead)
)

// Sentinel errors — use errors.Is for matching.
var (
	ErrKeyfileNotFound = errors.New("plutus/wallet: keyfile not found")
	ErrKeyfileCorrupt  = errors.New("plutus/wallet: keyfile corrupt or truncated")
	ErrBadPassphrase   = errors.New("plutus/wallet: bad passphrase (AEAD verify failed)")
	ErrKeyfileExists   = errors.New("plutus/wallet: keyfile already exists")
)

// EncryptedKeyfile is the decoded on-disk format.
//
// Binary layout (produced by Bytes, consumed by parseEncryptedKeyfile):
//
//	[salt:16][nonce:24][ciphertext+tag: len(plaintext)+16]
type EncryptedKeyfile struct {
	Salt       [saltSize]byte
	Nonce      [nonceSize]byte
	Ciphertext []byte // includes trailing Poly1305 tag
}

// Bytes serialises the keyfile to its on-disk binary form.
func (k *EncryptedKeyfile) Bytes() []byte {
	out := make([]byte, 0, saltSize+nonceSize+len(k.Ciphertext))
	out = append(out, k.Salt[:]...)
	out = append(out, k.Nonce[:]...)
	out = append(out, k.Ciphertext...)
	return out
}

// parseEncryptedKeyfile decodes the on-disk form. Anything shorter than the
// minimum envelope (salt + nonce + tag) is rejected as corrupt.
func parseEncryptedKeyfile(data []byte) (*EncryptedKeyfile, error) {
	if len(data) < saltSize+nonceSize+tagSize {
		return nil, ErrKeyfileCorrupt
	}
	var kf EncryptedKeyfile
	copy(kf.Salt[:], data[:saltSize])
	copy(kf.Nonce[:], data[saltSize:saltSize+nonceSize])
	kf.Ciphertext = append([]byte(nil), data[saltSize+nonceSize:]...)
	return &kf, nil
}

// sealPlaintext encrypts plaintext under passphrase, returning a populated
// EncryptedKeyfile. Generates fresh salt + nonce.
func sealPlaintext(passphrase, plaintext []byte) (*EncryptedKeyfile, error) {
	return sealPlaintextAD(passphrase, plaintext, keyfileAD)
}

// sealPlaintextAD is sealPlaintext with the associated data ad in place of
// keyfileAD, so another kind of sealed blob (SealMnemonic's) shares the
// cipher and never opens as a keyfile, nor a keyfile as it.
func sealPlaintextAD(passphrase, plaintext []byte, ad string) (*EncryptedKeyfile, error) {
	kf := &EncryptedKeyfile{}
	if _, err := rand.Read(kf.Salt[:]); err != nil {
		return nil, fmt.Errorf("plutus/wallet: salt generation failed: %w", err)
	}
	if _, err := rand.Read(kf.Nonce[:]); err != nil {
		return nil, fmt.Errorf("plutus/wallet: nonce generation failed: %w", err)
	}

	key := argon2.IDKey(passphrase, kf.Salt[:], argon2TimeV1, argon2MemoryV1, argon2ThreadsV1, argon2KeyLenV1)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: AEAD construction failed: %w", err)
	}

	kf.Ciphertext = aead.Seal(nil, kf.Nonce[:], plaintext, []byte(ad))
	return kf, nil
}

// openCiphertext decrypts the keyfile with passphrase. On AEAD failure
// (tamper, wrong passphrase) returns ErrBadPassphrase.
func (k *EncryptedKeyfile) openCiphertext(passphrase []byte) ([]byte, error) {
	return k.openCiphertextAD(passphrase, keyfileAD)
}

// openCiphertextAD is openCiphertext for a blob sealed by sealPlaintextAD
// with the associated data ad.
func (k *EncryptedKeyfile) openCiphertextAD(passphrase []byte, ad string) ([]byte, error) {
	key := argon2.IDKey(passphrase, k.Salt[:], argon2TimeV1, argon2MemoryV1, argon2ThreadsV1, argon2KeyLenV1)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: AEAD construction failed: %w", err)
	}
	plaintext, err := aead.Open(nil, k.Nonce[:], k.Ciphertext, []byte(ad))
	if err != nil {
		return nil, ErrBadPassphrase
	}
	return plaintext, nil
}

// WriteEncryptedKeyfile encrypts plaintext under passphrase and writes it to
// path with 0600 permissions. Returns ErrKeyfileExists if path already exists
// (callers must explicitly remove it first — we never overwrite silently, to
// avoid clobbering a key in a race with rewrap/rotate).
//
// The empty passphrase is permitted (see package doc). A nil plaintext is
// rejected as a programmer error.
func WriteEncryptedKeyfile(path string, passphrase, plaintext []byte) error {
	if path == "" {
		return errors.New("plutus/wallet: keyfile path is empty")
	}
	if plaintext == nil {
		return errors.New("plutus/wallet: plaintext is nil")
	}

	kf, err := sealPlaintext(passphrase, plaintext)
	if err != nil {
		return err
	}

	// O_EXCL forbids overwriting — this is the atomic "create if not exists"
	// primitive we need to avoid stomping an existing keyfile.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKeyfileExists, path)
		}
		return fmt.Errorf("plutus/wallet: create keyfile: %w", err)
	}

	if _, err := f.Write(kf.Bytes()); err != nil {
		_ = f.Close()
		_ = os.Remove(path) // best-effort cleanup of partial write
		return fmt.Errorf("plutus/wallet: write keyfile: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("plutus/wallet: close keyfile: %w", err)
	}
	return nil
}

// ReadEncryptedKeyfile loads path and decrypts it with passphrase. Errors
// surface distinctly:
//
//   - ErrKeyfileNotFound  — path does not exist
//   - ErrKeyfileCorrupt   — file shorter than salt+nonce+tag (truncated)
//   - ErrBadPassphrase    — AEAD verification failed (wrong passphrase or
//     ciphertext tamper; cryptographically indistinguishable and deliberately
//     collapsed into one error, per usual AEAD practice)
func ReadEncryptedKeyfile(path string, passphrase []byte) ([]byte, error) {
	if path == "" {
		return nil, errors.New("plutus/wallet: keyfile path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrKeyfileNotFound, path)
		}
		return nil, fmt.Errorf("plutus/wallet: read keyfile: %w", err)
	}

	kf, err := parseEncryptedKeyfile(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s (have %d bytes, need >=%d)",
			err, path, len(data), saltSize+nonceSize+tagSize)
	}
	return kf.openCiphertext(passphrase)
}

// RewrapKeyfile decrypts path with oldPassphrase and re-encrypts in place
// with newPassphrase, using a fresh salt and nonce. Atomic: writes to a
// sibling temp file (0600) and renames over the target. On any failure the
// temp file is removed and the original is left untouched.
//
// Use this for passphrase rotation — e.g. when a witness operator updates the
// payout-wallet passphrase after an operational handoff.
func RewrapKeyfile(path string, oldPassphrase, newPassphrase []byte) error {
	plaintext, err := ReadEncryptedKeyfile(path, oldPassphrase)
	if err != nil {
		return err
	}

	kf, err := sealPlaintext(newPassphrase, plaintext)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".rewrap-*")
	if err != nil {
		return fmt.Errorf("plutus/wallet: create rewrap temp: %w", err)
	}
	tmpName := tmp.Name()

	// Paranoid cleanup: if anything below fails, remove the temp.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("plutus/wallet: chmod rewrap temp: %w", err)
	}
	if _, err := tmp.Write(kf.Bytes()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("plutus/wallet: write rewrap temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("plutus/wallet: close rewrap temp: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("plutus/wallet: rename rewrap temp: %w", err)
	}
	success = true
	return nil
}

// --- Passphrase source helpers -----------------------------------------------

// PassphraseFromEnv reads the named environment variable, trimming trailing
// whitespace (common when values are piped in via `echo`). An empty or unset
// variable is returned as an empty byte slice — callers who require a
// non-empty passphrase must check themselves.
func PassphraseFromEnv(name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("plutus/wallet: env var name is empty")
	}
	return []byte(strings.TrimRight(os.Getenv(name), " \t\r\n")), nil
}

// PassphraseFromStdin prompts on stderr and reads a passphrase from stdin
// without echo when stdin is a terminal, or a single trimmed line otherwise.
// Intended for interactive CLIs (e.g. the ceremony tool).
func PassphraseFromStdin(prompt string) ([]byte, error) {
	if prompt != "" {
		fmt.Fprint(os.Stderr, prompt)
	}
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("plutus/wallet: read passphrase: %w", err)
		}
		return []byte(strings.TrimRight(string(pw), " \t\r\n")), nil
	}
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("plutus/wallet: read passphrase: %w", err)
	}
	return []byte(strings.TrimRight(line, " \t\r\n")), nil
}

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package wallet

import (
	"errors"
	"fmt"
)

// mnemonicExportAD is the associated data bound into every sealed mnemonic.
// It differs from keyfileAD, so a sealed mnemonic and a wallet keyfile,
// which share the cipher, never open as each other.
const mnemonicExportAD = "plutus-mnemonic-export-v1"

// ErrEmptyExportPassphrase is SealMnemonic's refusal of an empty passphrase:
// a mnemonic sealed under no secret would be the mnemonic in the clear.
var ErrEmptyExportPassphrase = errors.New("plutus/wallet: a sealed mnemonic needs a non-empty passphrase")

// SealedMnemonic is a wallet mnemonic encrypted under a passphrase, the form
// in which a holder that must be able to hand the mnemonic back later (the
// browser bridge's exportIdentity) keeps it instead of the mnemonic itself.
//
// Cipher and KDF: XChaCha20-Poly1305 under a 32-byte key derived from the
// passphrase by Argon2id (time 3, memory 64 MiB, 4 lanes; a random 16-byte
// salt per seal), with a random 24-byte nonce and mnemonicExportAD as the
// associated data: the wallet keyfile's construction (sealPlaintextAD).
type SealedMnemonic struct {
	sealed *EncryptedKeyfile
}

// SealMnemonic encrypts mnemonic under passphrase. An empty passphrase is
// refused with ErrEmptyExportPassphrase.
func SealMnemonic(mnemonic string, passphrase []byte) (*SealedMnemonic, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyExportPassphrase
	}
	sealed, err := sealPlaintextAD(passphrase, []byte(mnemonic), mnemonicExportAD)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: seal mnemonic: %w", err)
	}
	return &SealedMnemonic{sealed: sealed}, nil
}

// Open returns the mnemonic for the passphrase it was sealed under. Any
// other passphrase, or a copy altered since sealing, gets ErrBadPassphrase
// and an empty string: the authenticated cipher releases no plaintext
// unless the key derived from the passphrase is the sealing key.
func (s *SealedMnemonic) Open(passphrase []byte) (string, error) {
	plaintext, err := s.sealed.openCiphertextAD(passphrase, mnemonicExportAD)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

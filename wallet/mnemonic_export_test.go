/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package wallet

import (
	"bytes"
	"errors"
	"testing"
)

func TestASealedMnemonicOpensOnlyForItsPassphrase(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealMnemonic(mnemonic, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.sealed.Bytes(), []byte(mnemonic)) {
		t.Fatal("the sealed copy holds the mnemonic in the clear")
	}

	got, err := sealed.Open([]byte("correct horse battery staple"))
	if err != nil || got != mnemonic {
		t.Fatalf("Open with the sealing passphrase = %q, %v; want the mnemonic", got, err)
	}
	for _, wrong := range []string{"correct horse battery stapl", "Correct horse battery staple", "x"} {
		got, err := sealed.Open([]byte(wrong))
		if !errors.Is(err, ErrBadPassphrase) || got != "" {
			t.Fatalf("Open(%q) = %q, %v; want nothing and ErrBadPassphrase", wrong, got, err)
		}
	}
}

func TestSealMnemonicRefusesAnEmptyPassphrase(t *testing.T) {
	if s, err := SealMnemonic("abandon ability able", nil); !errors.Is(err, ErrEmptyExportPassphrase) || s != nil {
		t.Fatalf("SealMnemonic(nil passphrase) = %v, %v; want ErrEmptyExportPassphrase", s, err)
	}
}

// A sealed mnemonic and a wallet keyfile share the cipher; the associated
// data keeps either from opening as the other under the same passphrase.
func TestASealedMnemonicDoesNotOpenAsAKeyfile(t *testing.T) {
	pass := []byte("one passphrase for both")
	sealed, err := SealMnemonic("abandon ability able", pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.sealed.openCiphertext(pass); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("a sealed mnemonic opened as a keyfile: %v", err)
	}
	kf, err := sealPlaintext(pass, []byte("a keyfile's plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := (&SealedMnemonic{sealed: kf}).Open(pass); !errors.Is(err, ErrBadPassphrase) || got != "" {
		t.Fatalf("a keyfile opened as a sealed mnemonic: %q, %v", got, err)
	}
}

func TestEachSealOfOneMnemonicDiffers(t *testing.T) {
	a, err := SealMnemonic("abandon ability able", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealMnemonic("abandon ability able", []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.sealed.Bytes(), b.sealed.Bytes()) {
		t.Fatal("two seals of one mnemonic under one passphrase are identical: salt and nonce are not fresh")
	}
}

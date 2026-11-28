//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package main

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall/js"
	"testing"

	"github.com/bbmumford/plutus/wallet"
)

// createWith calls the JS-registered createWallet with config and returns its
// decoded answer.
func createWith(t *testing.T, plutus js.Value, config map[string]any) createdWallet {
	t.Helper()
	res, err := awaitPromise(t, plutus.Call("createWallet", js.ValueOf(config)))
	if err != nil {
		t.Fatalf("createWallet: %v", err)
	}
	var created createdWallet
	if err := json.Unmarshal([]byte(res.String()), &created); err != nil {
		t.Fatalf("createWallet answered %q: %v", res.String(), err)
	}
	return created
}

func registeredPlutus(t *testing.T) (js.Value, *jsBridge) {
	t.Helper()
	plutus := js.Global().Get("Object").New()
	b := newJSBridge()
	registerMethods(plutus, b, newPlutusRateLimiter())
	return plutus, b
}

func TestExportIdentityIsTheOnlyRegisteredWayToReadAMnemonic(t *testing.T) {
	plutus, _ := registeredPlutus(t)
	if plutus.Get("exportIdentity").Type() != js.TypeFunction {
		t.Fatal("Plutus.exportIdentity is not registered")
	}
	if !plutus.Get("walletMnemonic").IsUndefined() {
		t.Fatal("Plutus.walletMnemonic is registered")
	}
}

func TestCreateWalletReturnsTheMnemonicOnce(t *testing.T) {
	plutus, _ := registeredPlutus(t)
	fresh := createWith(t, plutus, map[string]any{})
	if fresh.Handle == 0 || len(strings.Fields(fresh.Mnemonic)) != 24 {
		t.Fatalf("a new wallet's answer = %+v; want its handle and a 24-word mnemonic", fresh)
	}
	mnemonic, err := wallet.GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	restored := createWith(t, plutus, map[string]any{"mnemonic": mnemonic})
	if restored.Mnemonic != mnemonic || restored.Handle == fresh.Handle {
		t.Fatalf("a restored wallet's answer = %+v; want a new handle and the mnemonic given", restored)
	}
}

// Only the passphrase the wallet was created with opens its sealed copy;
// every other passphrase is refused with nothing of the mnemonic, through
// the registered method as through the bridge.
func TestExportIdentityReturnsTheMnemonicOnlyForTheExportPassphrase(t *testing.T) {
	plutus, b := registeredPlutus(t)
	created := createWith(t, plutus, map[string]any{"exportPassphrase": "correct horse battery staple"})

	got, err := awaitPromise(t, plutus.Call("exportIdentity", created.Handle, "correct horse battery staple"))
	if err != nil || got.String() != created.Mnemonic {
		t.Fatalf("exportIdentity with the export passphrase = %v, %v; want the mnemonic", got, err)
	}
	got, err = awaitPromise(t, plutus.Call("exportIdentity", created.Handle, "correct horse battery stapl"))
	if err == nil {
		t.Fatalf("exportIdentity with a wrong passphrase answered %q; want a refusal", got.String())
	}
	words := strings.Fields(created.Mnemonic)
	for i := 0; i+1 < len(words); i++ {
		if strings.Contains(err.Error(), words[i]+" "+words[i+1]) {
			t.Fatalf("the refusal %q carries part of the mnemonic", err)
		}
	}

	for _, wrong := range []string{"correct horse battery stapl", "", "Correct horse battery staple"} {
		if m, err := b.exportMnemonic(created.Handle, wrong); err == nil || m != "" {
			t.Fatalf("exportMnemonic(%q) = %q, %v; want nothing and an error", wrong, m, err)
		}
	}
}

// exportIdentity hands out identity material, so the page gets it at the
// identity-material rate (two at once, five a minute): a script guessing
// passphrases is refused long before it could try many.
func TestExportIdentityIsRateLimitedAsIdentityMaterial(t *testing.T) {
	plutus, _ := registeredPlutus(t)
	created := createWith(t, plutus, map[string]any{"exportPassphrase": "pass"})
	for i := 0; i < 2; i++ {
		if _, err := awaitPromise(t, plutus.Call("exportIdentity", created.Handle, "pass")); err != nil {
			t.Fatalf("call %d within the burst: %v", i+1, err)
		}
	}
	got, err := awaitPromise(t, plutus.Call("exportIdentity", created.Handle, "pass"))
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("a third call at once = %q, %v; want the rate-limit refusal", got.String(), err)
	}
}

func TestAWalletCreatedWithoutAnExportPassphraseHasNothingToExport(t *testing.T) {
	plutus, b := registeredPlutus(t)
	created := createWith(t, plutus, map[string]any{})
	if m, err := b.exportMnemonic(created.Handle, ""); !errors.Is(err, errNoExportCopy) || m != "" {
		t.Fatalf("exportMnemonic = %q, %v; want nothing and errNoExportCopy", m, err)
	}
	if _, err := awaitPromise(t, plutus.Call("exportIdentity", created.Handle, "anything")); err == nil {
		t.Fatal("exportIdentity answered for a wallet created without an export passphrase")
	}
}

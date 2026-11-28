//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"syscall/js"
	"testing"
	"time"

	"github.com/bbmumford/plutus/wallet"
)

// awaitPromise waits for a JS promise and returns its value or its
// rejection's message as an error.
func awaitPromise(t *testing.T, p js.Value) (js.Value, error) {
	t.Helper()
	type settled struct {
		v   js.Value
		err error
	}
	ch := make(chan settled, 1)
	onOK := js.FuncOf(func(_ js.Value, args []js.Value) any { ch <- settled{v: args[0]}; return nil })
	onErr := js.FuncOf(func(_ js.Value, args []js.Value) any {
		ch <- settled{err: errors.New(args[0].Get("message").String())}
		return nil
	})
	defer onOK.Release()
	defer onErr.Release()
	p.Call("then", onOK, onErr)
	select {
	case s := <-ch:
		return s.v, s.err
	case <-time.After(60 * time.Second):
		t.Fatal("promise not settled within 60s")
		return js.Undefined(), nil
	}
}

// handleOf reads the wallet handle from createWallet's answer, a number or a
// JSON object holding "handle".
func handleOf(t *testing.T, v js.Value) int64 {
	t.Helper()
	if v.Type() == js.TypeNumber {
		return int64(v.Float())
	}
	var created struct {
		Handle int64 `json:"handle"`
	}
	if err := json.Unmarshal([]byte(v.String()), &created); err != nil {
		t.Fatalf("createWallet answered %q: %v", v.String(), err)
	}
	return created.Handle
}

// holdsInTheClear reports the path of the first string or byte field under
// v (followed through pointers, three levels deep) that is or contains
// secret, or "" when none does.
func holdsInTheClear(v reflect.Value, secret, path string, depth int) string {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || depth == 0 {
			return ""
		}
		return holdsInTheClear(v.Elem(), secret, path, depth-1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if p := holdsInTheClear(v.Field(i), secret, path+"."+v.Type().Field(i).Name, depth); p != "" {
				return p
			}
		}
	case reflect.String:
		if v.String() == secret {
			return path
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 && bytes.Contains(v.Bytes(), []byte(secret)) {
			return path
		}
	}
	return ""
}

// The mnemonic rebuilds every key of a wallet, so the bridge must not keep
// it in the page's heap once the wallet exists: the seed and keys are what
// every later operation reads.
func TestTheBridgeKeepsNoCopyOfAWalletsMnemonicInTheClear(t *testing.T) {
	mnemonic, err := wallet.GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	b := newJSBridge()
	cfg := js.Global().Get("Object").New()
	cfg.Set("mnemonic", mnemonic)
	cfg.Set("exportPassphrase", "a passphrase the page asked for")

	res, err := awaitPromise(t, b.createWallet(js.Undefined(), []js.Value{cfg}).(js.Value))
	if err != nil {
		t.Fatalf("createWallet: %v", err)
	}
	handle := handleOf(t, res)
	b.mu.RLock()
	ws := b.wallets[handle]
	b.mu.RUnlock()
	if ws == nil {
		t.Fatalf("no wallet under handle %d", handle)
	}
	if path := holdsInTheClear(reflect.ValueOf(ws), mnemonic, "walletState", 3); path != "" {
		t.Fatalf("the bridge keeps the wallet's mnemonic in the clear at %s", path)
	}
}

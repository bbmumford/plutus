/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package gossipstate

import "testing"

func TestFingerprintIsOrderIndependentAndContentDerived(t *testing.T) {
	a, b, c := []byte("alpha"), []byte("beta"), []byte("gamma")
	if Fingerprint(nil) != 0 {
		t.Fatal("an empty record set must fingerprint to 0")
	}
	if Fingerprint([][]byte{a, b}) != Fingerprint([][]byte{b, a}) {
		t.Fatal("record order must not change the fingerprint")
	}
	if Fingerprint([][]byte{a, b}) == Fingerprint([][]byte{a, c}) {
		t.Fatal("two sets of the same size with different records must differ")
	}
}

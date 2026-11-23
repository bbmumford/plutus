/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package plutus

import "github.com/bbmumford/plutus/canonical"

// ProtocolFingerprint returns the unique fingerprint for this Plutus deployment.
// Delegates to canonical.ProtocolFingerprint.
func ProtocolFingerprint() string { return canonical.ProtocolFingerprint() }

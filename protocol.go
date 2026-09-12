/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package plutus

import "github.com/bbmumford/plutus/canonical"

// ProtocolFingerprint returns the unique fingerprint for this Plutus deployment.
// Delegates to canonical.ProtocolFingerprint.
func ProtocolFingerprint() string { return canonical.ProtocolFingerprint() }

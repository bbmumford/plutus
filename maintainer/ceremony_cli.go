/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package maintainer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ceremony_cli.go provides the interactive ceremony tool functions.
//
// Step 1 (air-gapped): go run ./maintainer/ ceremony --generate-root --output root.key
//   Generates Offline Root keypair, encrypts and saves.
//   Prints OR public key for embedding.
//
// Step 2 (air-gapped): go run ./maintainer/ ceremony --sign-platform --root-key root.key --output platform.cert
//   Generates Platform Key, signs cert with OR.
//   Prints PK public key and cert for embedding.
//
// Step 3 (online): go run ./maintainer/ ceremony --certify-prc --platform-key pk.key --chain polygon --prc-addr 0x... --tx-hash 0x... --block 12345
//   Signs a PRC deployment certificate.
//   Prints deployment cert for embedding.
//
// Step 4: go run ./maintainer/ ceremony --emit-canonical
//   Reads all certs and prints the Go source for canonical.go with all
//   the embedded trust chain data filled in.

// offlineRootKeyFile is the on-disk format for an offline root key.
type offlineRootKeyFile struct {
	Version             int    `json:"version"`
	PublicKey           string `json:"publicKey"`           // hex-encoded
	EncryptedPrivateKey string `json:"encryptedPrivateKey"` // hex-encoded
}

// platformKeyFile is the on-disk format for a platform key (private key, encrypted).
type platformKeyFile struct {
	Version             int    `json:"version"`
	PublicKey           string `json:"publicKey"`           // hex-encoded
	EncryptedPrivateKey string `json:"encryptedPrivateKey"` // hex-encoded
}

// CeremonyGenerateRoot generates the air-gapped offline root keypair, encrypts
// the private key, and saves it to outputPath.
func CeremonyGenerateRoot(passphrase, outputPath string) error {
	if passphrase == "" {
		return fmt.Errorf("maintainer/ceremony: passphrase is required")
	}
	if outputPath == "" {
		return fmt.Errorf("maintainer/ceremony: output path is required")
	}

	key, encryptedPriv, err := GenerateOfflineRoot(passphrase)
	if err != nil {
		return err
	}

	// Save the key file.
	keyFile := offlineRootKeyFile{
		Version:             1,
		PublicKey:           hex.EncodeToString(key.PublicKey),
		EncryptedPrivateKey: hex.EncodeToString(encryptedPriv),
	}

	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: marshal root key file: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("maintainer/ceremony: write root key file: %w", err)
	}

	fmt.Printf("Offline Root Key Generated\n")
	fmt.Printf("==========================\n")
	fmt.Printf("Public Key (hex): %s\n", keyFile.PublicKey)
	fmt.Printf("Key file saved to: %s\n", outputPath)
	fmt.Printf("\nStore this key file in a secure, air-gapped vault.\n")
	fmt.Printf("The passphrase is needed to decrypt the private key for future ceremonies.\n")

	return nil
}

// CeremonySignPlatform generates a Platform Key, signs its certificate with the
// Offline Root, and saves both the platform key and certificate.
func CeremonySignPlatform(rootKeyPath, passphrase, outputPath string) error {
	if rootKeyPath == "" {
		return fmt.Errorf("maintainer/ceremony: root key path is required")
	}
	if passphrase == "" {
		return fmt.Errorf("maintainer/ceremony: passphrase is required")
	}
	if outputPath == "" {
		return fmt.Errorf("maintainer/ceremony: output path is required")
	}

	// Load the offline root key.
	rootData, err := os.ReadFile(rootKeyPath)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: read root key file: %w", err)
	}

	var rootFile offlineRootKeyFile
	if err := json.Unmarshal(rootData, &rootFile); err != nil {
		return fmt.Errorf("maintainer/ceremony: parse root key file: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(rootFile.PublicKey)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: decode root public key: %w", err)
	}

	encryptedPriv, err := hex.DecodeString(rootFile.EncryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: decode root encrypted private key: %w", err)
	}

	offlineRoot, err := DecryptOfflineRoot(ed25519.PublicKey(pubKeyBytes), encryptedPriv, passphrase)
	if err != nil {
		return err
	}

	// Generate Platform Key and sign cert.
	cert, platformPriv, err := GeneratePlatformKey(offlineRoot)
	if err != nil {
		return err
	}

	// Save the platform certificate.
	certPath := outputPath + ".cert"
	if err := SavePlatformCert(certPath, cert); err != nil {
		return err
	}

	// Save the encrypted platform private key.
	platformEncrypted, err := encryptPrivateKey(platformPriv, passphrase)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: encrypt platform key: %w", err)
	}

	pkFile := platformKeyFile{
		Version:             1,
		PublicKey:           hex.EncodeToString(cert.PlatformPubKey),
		EncryptedPrivateKey: hex.EncodeToString(platformEncrypted),
	}

	pkData, err := json.MarshalIndent(pkFile, "", "  ")
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: marshal platform key file: %w", err)
	}

	keyPath := outputPath + ".key"
	if err := os.WriteFile(keyPath, pkData, 0600); err != nil {
		return fmt.Errorf("maintainer/ceremony: write platform key file: %w", err)
	}

	fmt.Printf("Platform Key Generated and Certified\n")
	fmt.Printf("=====================================\n")
	fmt.Printf("Platform Public Key (hex): %s\n", hex.EncodeToString(cert.PlatformPubKey))
	fmt.Printf("Offline Root Public Key (hex): %s\n", hex.EncodeToString(cert.OfflineRootPubKey))
	fmt.Printf("Issued At: %s\n", cert.IssuedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Printf("Certificate saved to: %s\n", certPath)
	fmt.Printf("Encrypted key saved to: %s\n", keyPath)

	return nil
}

// CertifyPRCDeployment signs a PRC deployment certificate with the Platform Key.
//
// Since the switch to CREATE2 deployment via the Safe Singleton Factory, the
// PRC contract resides at the same deterministic address
// (canonical.CanonicalPRCAddress) on every EVM chain. Therefore prcAddr is
// expected to be identical across all per-chain certificates this function
// produces — the caller should pass canonical.CanonicalPRCAddress for every
// chain. The certificate still captures the per-chain (deployTxHash,
// blockNumber) pair so the on-chain deployment can be independently verified
// against each chain's ledger.
//
// The serialized certificate format is unchanged so existing parsers (embed
// loaders, trust-chain verifiers) continue to work without modification.
func CertifyPRCDeployment(platformKeyPath, passphrase, chainID, prcAddr, txHash string, blockNum uint64, outputPath string) error {
	if platformKeyPath == "" {
		return fmt.Errorf("maintainer/ceremony: platform key path is required")
	}
	if passphrase == "" {
		return fmt.Errorf("maintainer/ceremony: passphrase is required")
	}
	if chainID == "" {
		return fmt.Errorf("maintainer/ceremony: chain ID is required")
	}
	if prcAddr == "" {
		return fmt.Errorf("maintainer/ceremony: PRC address is required")
	}
	if txHash == "" {
		return fmt.Errorf("maintainer/ceremony: tx hash is required")
	}
	if outputPath == "" {
		return fmt.Errorf("maintainer/ceremony: output path is required")
	}

	// Load the platform private key.
	pkData, err := os.ReadFile(platformKeyPath)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: read platform key file: %w", err)
	}

	var pkFile platformKeyFile
	if err := json.Unmarshal(pkData, &pkFile); err != nil {
		return fmt.Errorf("maintainer/ceremony: parse platform key file: %w", err)
	}

	encryptedPriv, err := hex.DecodeString(pkFile.EncryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: decode platform encrypted private key: %w", err)
	}

	platformPriv, err := decryptPrivateKey(encryptedPriv, passphrase)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: decrypt platform key: %w", err)
	}

	// Sign the deployment certificate.
	deployCert, err := SignPRCDeployment(chainID, prcAddr, txHash, blockNum, platformPriv)
	if err != nil {
		return err
	}

	// Save the deployment certificate.
	if err := SavePRCDeploymentCert(outputPath, deployCert); err != nil {
		return err
	}

	fmt.Printf("PRC Deployment Certified\n")
	fmt.Printf("========================\n")
	fmt.Printf("Chain: %s\n", deployCert.ChainID)
	fmt.Printf("PRC Address: %s\n", deployCert.PRCAddress)
	fmt.Printf("Deploy Tx Hash: %s\n", deployCert.DeployTxHash)
	fmt.Printf("Block Number: %d\n", deployCert.BlockNumber)
	fmt.Printf("Deployed At: %s\n", deployCert.DeployedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Printf("Certificate saved to: %s\n", outputPath)

	return nil
}

// EmitCanonicalSource reads all ceremony artifacts and prints the Go source code
// that can be pasted into canonical/canonical.go with all the embedded trust
// chain data filled in.
func EmitCanonicalSource(rootPubKeyPath, platformCertPath string, deployCertPaths []string) error {
	if rootPubKeyPath == "" {
		return fmt.Errorf("maintainer/ceremony: root public key path is required")
	}
	if platformCertPath == "" {
		return fmt.Errorf("maintainer/ceremony: platform cert path is required")
	}

	// Load the offline root public key.
	rootData, err := os.ReadFile(rootPubKeyPath)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: read root key file: %w", err)
	}

	var rootFile offlineRootKeyFile
	if err := json.Unmarshal(rootData, &rootFile); err != nil {
		return fmt.Errorf("maintainer/ceremony: parse root key file: %w", err)
	}

	rootPubKeyBytes, err := hex.DecodeString(rootFile.PublicKey)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: decode root public key: %w", err)
	}

	// Load the platform certificate.
	platformCertBytes, err := os.ReadFile(platformCertPath)
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: read platform cert: %w", err)
	}

	// Validate the platform cert parses correctly.
	var platformCert PlatformKeyCertificate
	if err := json.Unmarshal(platformCertBytes, &platformCert); err != nil {
		return fmt.Errorf("maintainer/ceremony: parse platform cert: %w", err)
	}

	// Load PRC deployment certificates.
	deployments := make(map[string][]byte)
	checkpoints := make(map[string]string)

	for _, path := range deployCertPaths {
		certBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("maintainer/ceremony: read deployment cert %s: %w", path, err)
		}

		var deployCert PRCDeploymentCertificate
		if err := json.Unmarshal(certBytes, &deployCert); err != nil {
			return fmt.Errorf("maintainer/ceremony: parse deployment cert %s: %w", path, err)
		}

		deployments[deployCert.ChainID] = certBytes
		checkpoints[deployCert.ChainID] = deployCert.DeployTxHash
	}

	// Emit Go source.
	var sb strings.Builder

	sb.WriteString("// Generated by maintainer ceremony. Do not edit manually.\n\n")

	// Offline Root PubKey.
	sb.WriteString("OfflineRootPubKey: []byte{\n")
	emitByteSlice(&sb, rootPubKeyBytes)
	sb.WriteString("},\n\n")

	// Platform Cert (as raw JSON bytes).
	sb.WriteString("PlatformCert: []byte(`")
	sb.Write(platformCertBytes)
	sb.WriteString("`),\n\n")

	// PRC Deployments.
	sb.WriteString("PRCDeployments: map[string][]byte{\n")
	for chainID, certBytes := range deployments {
		sb.WriteString(fmt.Sprintf("\t%q: []byte(`", chainID))
		sb.Write(certBytes)
		sb.WriteString("`),\n")
	}
	sb.WriteString("},\n\n")

	// Checkpoints.
	sb.WriteString("Checkpoints: map[string]string{\n")
	for chainID, txHash := range checkpoints {
		sb.WriteString(fmt.Sprintf("\t%q: %q,\n", chainID, txHash))
	}
	sb.WriteString("},\n")

	// Also emit the MaintainerPubKeyHash (SHA-256 of the platform pub key,
	// for backward compatibility with the legacy single-key model).
	pkHash := sha256.Sum256(platformCert.PlatformPubKey)
	sb.WriteString("\n// MaintainerPubKeyHash (SHA-256 of Platform Public Key)\n")
	sb.WriteString(buildCanonicalSnippet(pkHash[:]))

	fmt.Print(sb.String())

	return nil
}

// emitByteSlice writes a byte slice as Go source code byte literals.
func emitByteSlice(sb *strings.Builder, data []byte) {
	for i, b := range data {
		if i%8 == 0 {
			sb.WriteString("\t")
		}
		sb.WriteString(fmt.Sprintf("0x%02x, ", b))
		if i%8 == 7 {
			sb.WriteString("\n")
		}
	}
	if len(data)%8 != 0 {
		sb.WriteString("\n")
	}
}

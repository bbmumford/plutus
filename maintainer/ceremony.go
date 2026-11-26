/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package maintainer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// OfflineRootKey represents the air-gapped root of trust.
// Generated ONCE during the initial ceremony. Never stored on a networked machine.
type OfflineRootKey struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey // only present during ceremony
}

// PlatformKeyCertificate is signed by the Offline Root to authorize a Platform Key.
type PlatformKeyCertificate struct {
	PlatformPubKey    ed25519.PublicKey `json:"platformPubKey"`
	OfflineRootPubKey ed25519.PublicKey `json:"offlineRootPubKey"`
	IssuedAt          time.Time         `json:"issuedAt"`
	Signature         []byte            `json:"signature"` // OR signs (PK pubkey + issuedAt)
	// NO expiry — valid forever unless revoked via rotation.
}

// PRCDeploymentCertificate records where the PRC was deployed, signed by Platform Key.
type PRCDeploymentCertificate struct {
	ChainID      string    `json:"chainID"`
	PRCAddress   string    `json:"prcAddress"`
	DeployTxHash string    `json:"deployTxHash"`
	BlockNumber  uint64    `json:"blockNumber"`
	DeployedAt   time.Time `json:"deployedAt"`
	Signature    []byte    `json:"signature"` // PK signs all above fields
}

// CeremonyResult holds the output of a key generation ceremony.
type CeremonyResult struct {
	// Key is the generated maintainer key metadata.
	Key *MaintainerKey
	// KeyFilePath is where the encrypted private key was saved.
	KeyFilePath string
	// CanonicalGoSnippet is the Go source for canonical.go with the pubkey hash.
	CanonicalGoSnippet string
	// DeployInstructions is the deployment command template.
	DeployInstructions string
}

// GenerateOfflineRoot creates the air-gapped root keypair.
// This should be run on an air-gapped machine. The private key
// is saved encrypted and should be stored in a secure vault.
// Returns: key, encrypted private key bytes, error.
func GenerateOfflineRoot(passphrase string) (*OfflineRootKey, []byte, error) {
	if passphrase == "" {
		return nil, nil, errors.New("maintainer/ceremony: passphrase is required for offline root key encryption")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/ceremony: generate offline root key: %w", err)
	}

	key := &OfflineRootKey{
		PublicKey:  pub,
		PrivateKey: priv,
	}

	// Encrypt the private key with Argon2id + XChaCha20-Poly1305.
	encryptedPriv, err := encryptPrivateKey(priv, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/ceremony: encrypt offline root key: %w", err)
	}

	return key, encryptedPriv, nil
}

// DecryptOfflineRoot decrypts an offline root private key from encrypted bytes.
func DecryptOfflineRoot(pubKey ed25519.PublicKey, encryptedPriv []byte, passphrase string) (*OfflineRootKey, error) {
	if passphrase == "" {
		return nil, errors.New("maintainer/ceremony: passphrase is required")
	}

	priv, err := decryptPrivateKey(encryptedPriv, passphrase)
	if err != nil {
		return nil, fmt.Errorf("maintainer/ceremony: decrypt offline root key: %w", err)
	}

	// Verify the decrypted key matches the public key.
	derivedPub := priv.Public().(ed25519.PublicKey)
	if !derivedPub.Equal(pubKey) {
		return nil, errors.New("maintainer/ceremony: decrypted key does not match expected public key")
	}

	return &OfflineRootKey{
		PublicKey:  pubKey,
		PrivateKey: priv,
	}, nil
}

// GeneratePlatformKey creates a new platform key and signs it with the offline root.
func GeneratePlatformKey(offlineRoot *OfflineRootKey) (*PlatformKeyCertificate, ed25519.PrivateKey, error) {
	if offlineRoot == nil {
		return nil, nil, errors.New("maintainer/ceremony: offline root key is nil")
	}
	if len(offlineRoot.PrivateKey) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("maintainer/ceremony: offline root private key is invalid")
	}

	// Generate a new Ed25519 keypair for the Platform Key.
	platformPub, platformPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/ceremony: generate platform key: %w", err)
	}

	now := time.Now().UTC()

	cert := &PlatformKeyCertificate{
		PlatformPubKey:    platformPub,
		OfflineRootPubKey: offlineRoot.PublicKey,
		IssuedAt:          now,
	}

	// Sign the certificate with the Offline Root key.
	payload := platformCertPayload(cert)
	cert.Signature = ed25519.Sign(offlineRoot.PrivateKey, payload)

	return cert, platformPriv, nil
}

// VerifyPlatformCert verifies the certificate chain: PK cert signed by OR.
func VerifyPlatformCert(cert *PlatformKeyCertificate) bool {
	if cert == nil {
		return false
	}
	if len(cert.PlatformPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(cert.OfflineRootPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(cert.Signature) == 0 {
		return false
	}

	payload := platformCertPayload(cert)
	return ed25519.Verify(cert.OfflineRootPubKey, payload, cert.Signature)
}

// SignPRCDeployment creates a signed record of a PRC deployment.
func SignPRCDeployment(chainID, prcAddr, txHash string, blockNum uint64, platformPrivKey ed25519.PrivateKey) (*PRCDeploymentCertificate, error) {
	if chainID == "" {
		return nil, errors.New("maintainer/ceremony: chainID is required")
	}
	if prcAddr == "" {
		return nil, errors.New("maintainer/ceremony: PRC address is required")
	}
	if txHash == "" {
		return nil, errors.New("maintainer/ceremony: deploy tx hash is required")
	}
	if len(platformPrivKey) != ed25519.PrivateKeySize {
		return nil, errors.New("maintainer/ceremony: invalid platform private key")
	}

	now := time.Now().UTC()

	cert := &PRCDeploymentCertificate{
		ChainID:      chainID,
		PRCAddress:   prcAddr,
		DeployTxHash: txHash,
		BlockNumber:  blockNum,
		DeployedAt:   now,
	}

	// Sign the deployment certificate with the Platform Key.
	payload := prcDeploymentPayload(cert)
	cert.Signature = ed25519.Sign(platformPrivKey, payload)

	return cert, nil
}

// VerifyPRCDeployment verifies a PRC deployment certificate against a platform cert.
func VerifyPRCDeployment(deployCert *PRCDeploymentCertificate, platformCert *PlatformKeyCertificate) bool {
	if deployCert == nil || platformCert == nil {
		return false
	}
	if len(deployCert.Signature) == 0 {
		return false
	}
	if len(platformCert.PlatformPubKey) != ed25519.PublicKeySize {
		return false
	}

	// Verify the platform cert itself is valid first.
	if !VerifyPlatformCert(platformCert) {
		return false
	}

	// Verify the deployment cert is signed by the platform key.
	payload := prcDeploymentPayload(deployCert)
	return ed25519.Verify(platformCert.PlatformPubKey, payload, deployCert.Signature)
}

// RunCeremony generates an Ed25519 keypair, saves the encrypted private key,
// and produces the Go source snippet and deployment instructions needed to
// finalize the canonical PRC addresses.
//
// This is the single-key ceremony. For the full trust chain ceremony,
// use GenerateOfflineRoot + GeneratePlatformKey.
func RunCeremony(outputKeyPath, passphrase string) (*CeremonyResult, error) {
	if outputKeyPath == "" {
		return nil, fmt.Errorf("maintainer/ceremony: output key path is required")
	}
	if passphrase == "" {
		return nil, fmt.Errorf("maintainer/ceremony: passphrase is required")
	}

	// 1. Generate Ed25519 keypair.
	key, privateKey, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("maintainer/ceremony: %w", err)
	}

	// 2. Save encrypted key to file.
	if err := SaveKey(outputKeyPath, key, privateKey, passphrase); err != nil {
		return nil, fmt.Errorf("maintainer/ceremony: %w", err)
	}

	// 3. Compute SHA-256(pubkey) for the canonical snippet.
	pubKeyHash := sha256.Sum256(key.PublicKey)

	// 4. Build the Go source snippet for canonical.go.
	goSnippet := buildCanonicalSnippet(pubKeyHash[:])

	// 5. Build deployment instructions.
	deployInstructions := buildDeployInstructions(key.PublicKeyHex, hex.EncodeToString(pubKeyHash[:]))

	return &CeremonyResult{
		Key:                key,
		KeyFilePath:        outputKeyPath,
		CanonicalGoSnippet: goSnippet,
		DeployInstructions: deployInstructions,
	}, nil
}

// platformCertPayload computes the canonical bytes for platform key certificate signing.
// Uses SHA-256 digest of canonical field concatenation.
func platformCertPayload(cert *PlatformKeyCertificate) []byte {
	h := sha256.New()
	h.Write([]byte("plutus:platform-cert:v1:"))
	h.Write(cert.PlatformPubKey)
	h.Write([]byte{0x00}) // separator for future-proofing
	h.Write(cert.OfflineRootPubKey)
	// Encode issuedAt as 8-byte big-endian Unix timestamp for determinism.
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(cert.IssuedAt.Unix()))
	h.Write(ts)
	return h.Sum(nil)
}

// prcDeploymentPayload computes the canonical bytes for PRC deployment certificate signing.
// Uses SHA-256 digest of canonical field concatenation.
func prcDeploymentPayload(cert *PRCDeploymentCertificate) []byte {
	h := sha256.New()
	h.Write([]byte("plutus:prc-deployment:v1:"))
	h.Write([]byte(cert.ChainID))
	h.Write([]byte(":"))
	h.Write([]byte(cert.PRCAddress))
	h.Write([]byte(":"))
	h.Write([]byte(cert.DeployTxHash))
	h.Write([]byte(":"))
	blockBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockBytes, cert.BlockNumber)
	h.Write(blockBytes)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(cert.DeployedAt.Unix()))
	h.Write(ts)
	return h.Sum(nil)
}

// encryptPrivateKey encrypts an Ed25519 private key with Argon2id + XChaCha20-Poly1305.
// Returns the raw encrypted blob: [salt:32][nonce:24][ciphertext].
func encryptPrivateKey(priv ed25519.PrivateKey, passphrase string) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	encKey := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(priv), nil)

	// Pack: salt || nonce || ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

// decryptPrivateKey decrypts an Ed25519 private key from the encrypted blob.
// Format: [salt:32][nonce:NonceSize][ciphertext].
func decryptPrivateKey(data []byte, passphrase string) (ed25519.PrivateKey, error) {
	if len(data) < 32 {
		return nil, errors.New("encrypted data too short")
	}

	salt := data[:32]

	encKey := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(data) < 32+nonceSize {
		return nil, errors.New("encrypted data too short")
	}
	nonce := data[32 : 32+nonceSize]
	ciphertext := data[32+nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed (wrong passphrase?): %w", err)
	}

	if len(plaintext) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decrypted key has invalid size %d", len(plaintext))
	}

	return ed25519.PrivateKey(plaintext), nil
}

// SavePlatformCert writes a platform key certificate to a JSON file.
func SavePlatformCert(path string, cert *PlatformKeyCertificate) error {
	if path == "" {
		return errors.New("maintainer/ceremony: file path is empty")
	}
	if cert == nil {
		return errors.New("maintainer/ceremony: certificate is nil")
	}

	data, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: marshal platform cert: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// LoadPlatformCert reads a platform key certificate from a JSON file.
func LoadPlatformCert(path string) (*PlatformKeyCertificate, error) {
	if path == "" {
		return nil, errors.New("maintainer/ceremony: file path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("maintainer/ceremony: read platform cert: %w", err)
	}

	var cert PlatformKeyCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("maintainer/ceremony: parse platform cert: %w", err)
	}

	return &cert, nil
}

// SavePRCDeploymentCert writes a PRC deployment certificate to a JSON file.
func SavePRCDeploymentCert(path string, cert *PRCDeploymentCertificate) error {
	if path == "" {
		return errors.New("maintainer/ceremony: file path is empty")
	}
	if cert == nil {
		return errors.New("maintainer/ceremony: certificate is nil")
	}

	data, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return fmt.Errorf("maintainer/ceremony: marshal deployment cert: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// LoadPRCDeploymentCert reads a PRC deployment certificate from a JSON file.
func LoadPRCDeploymentCert(path string) (*PRCDeploymentCertificate, error) {
	if path == "" {
		return nil, errors.New("maintainer/ceremony: file path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("maintainer/ceremony: read deployment cert: %w", err)
	}

	var cert PRCDeploymentCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("maintainer/ceremony: parse deployment cert: %w", err)
	}

	return &cert, nil
}

// buildCanonicalSnippet generates the Go source for the
// CanonicalMaintainerPubKeyHash variable with the actual hash bytes filled in.
func buildCanonicalSnippet(hash []byte) string {
	var sb strings.Builder
	sb.WriteString("var CanonicalMaintainerPubKeyHash = []byte{\n")
	for i, b := range hash {
		if i%8 == 0 {
			sb.WriteString("\t")
		}
		fmt.Fprintf(&sb, "0x%02x, ", b)
		if i%8 == 7 {
			sb.WriteString("\n")
		}
	}
	sb.WriteString("}\n")
	return sb.String()
}

// buildDeployInstructions generates the deployment command template.
func buildDeployInstructions(pubKeyHex, pubKeyHashHex string) string {
	return fmt.Sprintf(`Maintainer Key Ceremony Complete
=================================
Public Key (hex): %s
PubKey Hash (hex): %s

Next steps:
  1. Copy the CanonicalMaintainerPubKeyHash snippet into plutus/canonical.go
  2. Deploy the PRC ONCE via the Safe Singleton Factory (CREATE2). The same
     address will land on every supported EVM chain:
       cd contracts/evm && forge script script/Deploy.s.sol \
           --rpc-url $RPC_URL --broadcast --verify
     Run the same command per chain RPC — each transaction uses the same
     salt + initCode, so every chain ends up with an identical PRC address.
  3. Paste that single address into CanonicalPRCAddress in canonical.go.
     The per-chain PRC map is populated from it automatically.
  4. Run CertifyPRCDeployment per chain to sign the (txHash, blockNumber)
     certificate — the prcAddress field is identical across all certs.
  5. Tag a new release

The encrypted private key is saved to the specified output path.
Store the passphrase separately and securely.
`, pubKeyHex, pubKeyHashHex)
}

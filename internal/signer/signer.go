// Package signer produces and loads detached ed25519 signature bundles over a
// canonical manifest payload. It is fully offline and depends only on the Go
// standard library, so the whole sign -> verify loop runs with no network and
// no external trust roots. (A sigstore keyless path is intentionally left as a
// future, opt-in addition; the local key is the default and must always work.)
package signer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// small encoding helpers, named to keep the signing/verify code readable.
func b64(b []byte) string       { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// BundleFile is the canonical detached-signature filename.
const BundleFile = "bundle.sig"

// Bundle is the detached signature artifact written next to the manifest. It is
// self-describing: it carries the public key so a verifier with only the skill
// directory can check the signature (trust-on-first-use). Pinning the key to an
// external trust root is a deliberate non-goal for v0.1.
type Bundle struct {
	Scheme      string `json:"scheme"`       // "ed25519"
	PublicKey   string `json:"public_key"`   // base64 (std) ed25519 public key
	Signature   string `json:"signature"`    // base64 (std) signature over PayloadSHA256
	PayloadHash string `json:"payload_sha256"` // hex sha256 of the canonical manifest
}

// privPEMType / pubPEMType label the PEM blocks for the local key file.
const (
	privPEMType = "SKILLPROV ED25519 PRIVATE KEY"
	pubPEMType  = "SKILLPROV ED25519 PUBLIC KEY"
)

// LoadOrCreateKey loads an ed25519 private key from keyPath, generating and
// persisting a fresh key pair if the file does not yet exist. The key is stored
// as PEM so it is easy to inspect and commit-ignore.
func LoadOrCreateKey(keyPath string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return generateKey(keyPath)
	}
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != privPEMType {
		return nil, fmt.Errorf("%s: not a skillprov ed25519 private key", keyPath)
	}
	if len(blk.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: malformed private key length %d", keyPath, len(blk.Bytes))
	}
	return ed25519.PrivateKey(blk.Bytes), nil
}

// generateKey creates a new key pair and writes the private key (0600) to keyPath
// and the public key alongside it as <keyPath>.pub.
func generateKey(keyPath string) (ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(keyPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: privPEMType, Bytes: priv})
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: pubPEMType, Bytes: pub})
	if err := os.WriteFile(keyPath+".pub", pubPEM, 0o644); err != nil {
		return nil, err
	}
	return priv, nil
}

// Sign signs the canonical manifest payload and returns a detached bundle.
func Sign(priv ed25519.PrivateKey, payload []byte) *Bundle {
	sum := sha256.Sum256(payload)
	sig := ed25519.Sign(priv, sum[:])
	pub := priv.Public().(ed25519.PublicKey)
	return &Bundle{
		Scheme:      "ed25519",
		PublicKey:   b64(pub),
		Signature:   b64(sig),
		PayloadHash: hex.EncodeToString(sum[:]),
	}
}

// Write serializes the bundle to bundle.sig in dir.
func (b *Bundle) Write(dir string) error {
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, BundleFile), append(out, '\n'), 0o644)
}

// LoadBundle reads bundle.sig from dir.
func LoadBundle(dir string) (*Bundle, error) {
	raw, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse %s: %w", BundleFile, err)
	}
	return &b, nil
}

// Verify checks that the bundle's signature is valid for payload. It returns nil
// on success or a descriptive error explaining why the signature did not match
// (wrong scheme, tampered payload, bad signature).
func (b *Bundle) Verify(payload []byte) error {
	if b.Scheme != "ed25519" {
		return fmt.Errorf("unsupported signature scheme %q", b.Scheme)
	}
	pub, err := unb64(b.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key in bundle")
	}
	sig, err := unb64(b.Signature)
	if err != nil {
		return errors.New("invalid signature encoding in bundle")
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != b.PayloadHash {
		return errors.New("manifest digest does not match signed payload (manifest was modified after signing)")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), sum[:], sig) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

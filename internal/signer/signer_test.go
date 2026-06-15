package signer

import (
	"os"
	"path/filepath"
	"testing"
)

// readable reports whether a file exists and is readable.
func readable(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// A signed payload must verify; a tampered payload must not. This is the m2
// "tampered manifest fails the next verify" milestone, isolated to the signer.
func TestSignVerifyRoundtrip(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "dev.key")
	priv, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}

	payload := []byte(`{"schema":"skillprov/v0","skill":{"name":"x"}}`)
	b := Sign(priv, payload)

	if b.Scheme != "ed25519" {
		t.Errorf("scheme = %q, want ed25519", b.Scheme)
	}
	if err := b.Verify(payload); err != nil {
		t.Errorf("valid payload failed verification: %v", err)
	}

	// Tamper: any change to the payload must break verification.
	tampered := append([]byte{}, payload...)
	tampered[10] ^= 0xFF
	if err := b.Verify(tampered); err == nil {
		t.Errorf("tampered payload unexpectedly verified")
	}
}

// LoadOrCreateKey must persist the key so a second load returns the same key
// (sign on one run, verify on another).
func TestKeyPersistence(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "nested", "dev.key")
	p1, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	p2, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if p1.Equal(p2) == false {
		t.Errorf("reloaded key differs from the persisted one")
	}

	// A public .pub sidecar must have been written.
	if _, err := readable(keyPath + ".pub"); err != nil {
		t.Errorf("public key sidecar missing: %v", err)
	}
}

// Bundle.Write then LoadBundle must round-trip the detached signature.
func TestBundleWriteLoad(t *testing.T) {
	dir := t.TempDir()
	priv, err := LoadOrCreateKey(filepath.Join(dir, "dev.key"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello-skillprov")
	if err := Sign(priv, payload).Write(dir); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	got, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	if err := got.Verify(payload); err != nil {
		t.Errorf("round-tripped bundle failed verification: %v", err)
	}
}

// A bundle with an unsupported scheme must be rejected.
func TestRejectsUnknownScheme(t *testing.T) {
	b := &Bundle{Scheme: "rsa"}
	if err := b.Verify([]byte("x")); err == nil {
		t.Errorf("unsupported scheme was accepted")
	}
}

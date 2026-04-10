package hsm

import (
	"bytes"
	"context"
	"testing"
)

func TestSoftHSM_RoundTrip(t *testing.T) {
	h, err := NewSoftHSM()
	if err != nil {
		t.Fatalf("NewSoftHSM: %v", err)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	wrapped, err := h.WrapDEK(context.Background(), dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	got, err := h.UnwrapDEK(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip mismatch: got %x, want %x", got, dek)
	}
}

func TestSoftHSM_NonceUnique(t *testing.T) {
	h, err := NewSoftHSM()
	if err != nil {
		t.Fatalf("NewSoftHSM: %v", err)
	}
	dek := make([]byte, 32)
	w1, _ := h.WrapDEK(context.Background(), dek)
	w2, _ := h.WrapDEK(context.Background(), dek)
	if bytes.Equal(w1, w2) {
		t.Fatal("expected distinct ciphertexts for two WrapDEK calls (nonce reuse detected)")
	}
}

func TestSoftHSM_Ping(t *testing.T) {
	h, err := NewSoftHSM()
	if err != nil {
		t.Fatalf("NewSoftHSM: %v", err)
	}
	if err := h.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestSoftHSM_TamperedCiphertext(t *testing.T) {
	h, err := NewSoftHSM()
	if err != nil {
		t.Fatalf("NewSoftHSM: %v", err)
	}
	dek := make([]byte, 32)
	wrapped, _ := h.WrapDEK(context.Background(), dek)
	wrapped[len(wrapped)-1] ^= 0xFF
	if _, err := h.UnwrapDEK(context.Background(), wrapped); err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

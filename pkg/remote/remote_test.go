package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeKMS is a minimal in-memory KMS that base64-encodes on wrap and decodes on unwrap.
type fakeKMS struct {
	failCount int
	calls     int
}

func (f *fakeKMS) handler(w http.ResponseWriter, r *http.Request) {
	f.calls++
	if f.failCount > 0 {
		f.failCount--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// wrap: echo input as ciphertext; unwrap: decode and re-encode as plaintext
	if v, ok := req["plaintext"]; ok {
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": v})
		return
	}
	if v, ok := req["ciphertext"]; ok {
		json.NewEncoder(w).Encode(map[string]string{"plaintext": v})
		return
	}
	http.Error(w, "unknown request", http.StatusBadRequest)
}

func newTestServer(t *testing.T, f *fakeKMS) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	return srv
}

func TestProvider_WrapUnwrap(t *testing.T) {
	f := &fakeKMS{}
	srv := newTestServer(t, f)
	cfg := Config{
		URL:                    srv.URL,
		WrapRequestTemplate:    `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath:   "ciphertext",
		UnwrapRequestTemplate:  `{"ciphertext":"{{.Wrapped}}"}`,
		UnwrapResponseJSONPath: "plaintext",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	wrapped, err := p.WrapDEK(context.Background(), dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	got, err := p.UnwrapDEK(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	gotDecoded, err := base64.StdEncoding.DecodeString(string(got))
	if err != nil {
		gotDecoded = got
	}
	_ = gotDecoded
}

func TestProvider_RetryOn503(t *testing.T) {
	f := &fakeKMS{failCount: 2}
	srv := newTestServer(t, f)
	cfg := Config{
		URL:                    srv.URL,
		WrapRequestTemplate:    `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath:   "ciphertext",
		UnwrapRequestTemplate:  `{"ciphertext":"{{.Wrapped}}"}`,
		UnwrapResponseJSONPath: "plaintext",
		RetryCount:             3,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := p.WrapDEK(context.Background(), dek); err != nil {
		t.Fatalf("WrapDEK after retries: %v", err)
	}
	if f.calls < 3 {
		t.Fatalf("expected at least 3 HTTP calls (2 failures + 1 success), got %d", f.calls)
	}
}

func TestProvider_Ping(t *testing.T) {
	f := &fakeKMS{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		f.handler(w, r)
	}))
	t.Cleanup(srv.Close)

	p, err := New(Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// TestContextCancellation verifies that WrapDEK respects context cancellation.
// The fake KMS sleeps for 5 seconds; the context has a 200ms deadline.
// The call must return an error well before the 5-second server delay.
func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow/hung KMS.
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		URL:                  srv.URL,
		WrapRequestTemplate:  `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath: "ciphertext",
		// Use a long client timeout so it doesn't interfere with our context deadline.
		Timeout:    10 * time.Second,
		RetryCount: 0,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(200*time.Millisecond))
	defer cancel()

	start := time.Now()
	_, err = p.WrapDEK(ctx, make([]byte, 32))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected WrapDEK to return an error when context is cancelled")
	}
	// Must return within 500ms, not after the 5-second server sleep.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("WrapDEK took %v; expected cancellation within 500ms", elapsed)
	}
}

// TestResponseSizeLimitExceeded verifies that an oversized KMS response is handled
// safely. The fake KMS returns a JSON body whose "ciphertext" field contains
// 128 KiB of random base64 data. The 64 KiB response cap truncates the JSON
// mid-stream, so JSON unmarshalling must fail — preventing OOM from an
// unbounded read.
func TestResponseSizeLimitExceeded(t *testing.T) {
	// Build 96 KiB of random bytes and base64-encode them so the JSON response
	// body well exceeds the 64 KiB cap.
	oversizedPayload := make([]byte, 96*1024)
	rand.Read(oversizedPayload) //nolint:gosec // test randomness, not cryptographic
	encoded := base64.StdEncoding.EncodeToString(oversizedPayload)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write a JSON object whose total size exceeds 64 KiB.
		w.Write([]byte(`{"ciphertext":"`))
		w.Write([]byte(encoded))
		w.Write([]byte(`"}`))
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		URL:                  srv.URL,
		WrapRequestTemplate:  `{"plaintext":"{{.DEK}}"}`,
		WrapResponseJSONPath: "ciphertext",
		RetryCount:           0,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.WrapDEK(context.Background(), make([]byte, 32))
	if err == nil {
		t.Fatal("expected WrapDEK to return an error for oversized response body")
	}
}

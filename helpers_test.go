package secretengine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(t *testing.T) (*netboxBackend, logical.Storage) {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*netboxBackend), cfg.StorageView
}

func testBackendWithNetbox(t *testing.T, handler http.HandlerFunc) (*netboxBackend, logical.Storage, *httptest.Server) {
	t.Helper()

	b, storage := testBackend(t)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": srv.URL, "token": "test"},
		Storage:   storage,
	})
	if err != nil || resp.IsError() {
		t.Fatalf("harness: configuring backend failed: err=%v resp=%v", err, resp)
	}

	return b, storage, srv
}

func netboxUserFound(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("username")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"count":1,"results":[{"id":42,"username":%q}]}`, u)
}

func netboxNoUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"count":0,"results":[]}`))
}

func assertUserError(t *testing.T, resp *logical.Response, mustContain string) {
	t.Helper()
	if resp == nil || !resp.IsError() { // nil guards the (nil, err) 5xx case
		t.Fatalf("expected a user error, got resp=%v", resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(msg, mustContain) {
		t.Fatalf("user error %q did not mention %q", msg, mustContain)
	}
}

func assertSingleWarning(t *testing.T, resp *logical.Response, mustContain string) {
	t.Helper()
	if resp == nil {
		t.Fatalf("got nil, want resp")
	}

	// We expect exactly one warning
	if len(resp.Warnings) != 1 {
		t.Fatalf("got %d warnings, want 1: %q", len(resp.Warnings), resp.Warnings)
	}

	if !strings.Contains(strings.ToLower(resp.Warnings[0]), strings.ToLower(mustContain)) {
		t.Fatalf("%q not in warning, got %q", mustContain, resp.Warnings[0])
	}
}

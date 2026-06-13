package secretengine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// Asserts that we did not receive an error
func assertNotFatal(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("want nil, got fatal err: %v", err)
	}
}

func assertOK(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	assertNotFatal(t, err)
	if resp.IsError() {
		t.Fatalf("want nil, got resp.ErrorResponse: %v", resp.Error())
	}
}

// Asserts that resp.IsError() is true and that the error message contains a given string
func assertError(t *testing.T, resp *logical.Response, err error, mustContain string) {
	t.Helper()
	assertNotFatal(t, err)
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected a user error, got resp=%v", resp)
	}
	if msg := resp.Error().Error(); !strings.Contains(strings.ToLower(msg), strings.ToLower(mustContain)) {
		t.Fatalf("user error %q did not mention %q", msg, mustContain)
	}
}

// Asserts that len(resp.Warnings) == 1 and that the warning message contains a given string
func assertSingleWarning(t *testing.T, resp *logical.Response, err error, mustContain string) {
	t.Helper()

	assertOK(t, resp, err)

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

func assertDefault(t *testing.T, resp *logical.Response, field string, value any) {
	t.Helper()
	if !reflect.DeepEqual(resp.Data[field], value) {
		t.Fatalf(`create didn't set default for %q: wanted %v, got %v`, field, value, resp.Data[field])
	}
}

// Creates a role "test" with given data values
func roleCreate(t *testing.T, b *netboxBackend, storage logical.Storage, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test",
		Data:      data,
		Storage:   storage,
	})
}

// Creates a role "test" with default values (username "test")
func roleCreateDefault(t *testing.T, b *netboxBackend, storage logical.Storage) (*logical.Response, error) {
	t.Helper()
	return roleCreate(t, b, storage, map[string]any{"username": "test"})
}

func roleUpdate(t *testing.T, b *netboxBackend, storage logical.Storage, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test",
		Data:      data,
		Storage:   storage,
	})
}

func roleRead(t *testing.T, b *netboxBackend, storage logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test",
		Storage:   storage,
	})
}

func roleDelete(t *testing.T, b *netboxBackend, storage logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/test",
		Storage:   storage,
	})
}

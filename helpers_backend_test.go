// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func netboxDeleteToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(204)
	w.Write([]byte{})
}

func netboxResponds404(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(404)
	w.Write([]byte{})
}

func netboxResponds500(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(500)
	w.Write([]byte{})
}

// renewHandler builds an httptest handler for renewal tests. It resolves the
// role's user (role creation needs it), serves /api/status/ with the given
// NetBox version (renewToken probes it via renewRequiresKey), and routes the
// PATCH of token 42 to patch. Any other request fails the test.
func renewHandler(t *testing.T, version string, patch http.HandlerFunc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users/users/" && r.Method == http.MethodGet:
			netboxUserFound(w, r)
		case r.URL.Path == "/api/status/" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"netbox-version": %q}`, version)
		case r.URL.Path == "/api/users/tokens/42/" && r.Method == http.MethodPatch:
			patch(w, r)
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}
}

// capturePatch returns a PATCH responder that decodes the JSON request body
// into *dst and replies 204.
func capturePatch(t *testing.T, dst *map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
			t.Errorf("Unparseable request body: %v", err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}
}

// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestSecretToken_RevokeDeletesByID(t *testing.T) {
	// Create backend handler we can watch
	var gotPath string
	var gotMethod string
	var hits int
	handler := func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath = r.URL.Path
		gotMethod = r.Method
		netboxDeleteToken(w, r) // reuse the existing stub for the response body
	}

	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Delete a token
	resp, err := tokenRevoke(t, backend, storage, 42)
	assertOK(t, resp, err)

	// Assert our spy got hit and we got the correct ID and method
	assertEqual(t, 1, hits)
	assertEqual(t, "/api/users/tokens/42/", gotPath)
	assertEqual(t, "DELETE", gotMethod)
}

func TestSecretToken_RevokeTolerates404(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxResponds404)

	// Delete a token
	resp, err := tokenRevoke(t, backend, storage, 42)
	assertOK(t, resp, err)
}

func TestSecretToken_RevokeFatalWhenNetboxDown(t *testing.T) {
	// Create mock backend, then kill it
	backend, storage, srv := testBackendWithNetbox(t, netboxResponds404)
	srv.Close()

	// Delete a token
	resp, err := tokenRevoke(t, backend, storage, 42)

	// Assert that this actually failed
	assertFatal(t, resp, err, "request failure")
}

func TestSecretToken_RevokeFatalWhenNetboxErrors(t *testing.T) {
	// Create backend handler we can watch
	var gotPath string
	var gotMethod string
	var hits int
	handler := func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath = r.URL.Path
		gotMethod = r.Method
		netboxResponds500(w, r) // reuse the existing stub for the response body
	}

	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Delete a token
	resp, err := tokenRevoke(t, backend, storage, 42)
	assertFatal(t, resp, err, "unexpected status")

	// Assert our spy got hit and we got the correct ID and method
	assertEqual(t, 1, hits)
	assertEqual(t, "/api/users/tokens/42/", gotPath)
	assertEqual(t, "DELETE", gotMethod)
}

func TestSecretToken_RenewUpdatesNetboxExpire(t *testing.T) {
	tests := []struct {
		name             string
		increment        time.Duration
		wantEffectiveTTL time.Duration
	}{
		{
			name:             "increment default",
			wantEffectiveTTL: 24 * time.Hour,
		},
		{
			name:             "increment override",
			increment:        1 * time.Hour,
			wantEffectiveTTL: time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody map[string]any

			handler := func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/users/users/" && r.Method == "GET":
					netboxUserFound(w, r)
				case r.URL.Path == "/api/users/tokens/42/" && r.Method == "PATCH":
					// decode request
					data := map[string]any{}
					if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
						t.Errorf("Unparseable request body: %v", err)
						w.WriteHeader(500)
						return
					}

					// Store body so we can assert it later
					gotBody = data

					// Respond to the token request
					w.WriteHeader(204)
					w.Write([]byte{})

				default:
					t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
				}
			}

			// Create mock backend
			backend, storage, _ := testBackendWithNetbox(t, handler)

			// Write test role
			resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test"})
			assertOK(t, resp, err)

			// Renew the token
			resp, err = tokenRenew(t, backend, storage, 42, "test", tt.increment)
			assertOK(t, resp, err)

			// Assert the token expire time
			assertExpireTime(t, gotBody, tt.wantEffectiveTTL)
		})
	}
}

func TestSecretToken_RenewRespectsIssueTime(t *testing.T) {
	var gotBody map[string]any

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/users/tokens/42/" && r.Method == "PATCH":
			// decode request
			data := map[string]any{}
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
				t.Errorf("Unparseable request body: %v", err)
				w.WriteHeader(500)
				return
			}

			// Store body so we can assert it later
			gotBody = data

			// Respond to the token request
			w.WriteHeader(204)
			w.Write([]byte{})

		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}

	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Write test role that wants a full hour but is capped at a one hour max
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{
		"username": "test",
		"ttl":      time.Hour,
		"max_ttl":  time.Hour,
	})
	assertOK(t, resp, err)

	// Renew a token that was issued 45 minutes ago
	issued := time.Now().Add(-45 * time.Minute)
	resp, err = tokenRenewAt(t, backend, storage, 42, "test", 0, issued)
	assertOK(t, resp, err)

	// Assert the token only has the 15 minutes left on its max_ttl, not a fresh hour
	assertExpireTime(t, gotBody, 15*time.Minute)
}

func TestSecretToken_RenewFatalWhenNetboxDown(t *testing.T) {
	// Create mock backend
	backend, storage, srv := testBackendWithNetbox(t, netboxUserFound)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// kill netbox backend
	srv.Close()

	// Renew a token
	resp, err = tokenRenew(t, backend, storage, 42, "test", 0*time.Hour)

	// Assert that this actually failed
	assertFatal(t, resp, err, "request failure")
}

func TestSecretToken_RenewFatalWhenNetboxErrors(t *testing.T) {
	// Create backend handler we can watch
	var gotPath string
	var gotMethod string
	var hits int

	// Create custom handler to error after role setup
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/users/tokens/42/" && r.Method == "PATCH":
			hits++
			gotPath = r.URL.Path
			gotMethod = r.Method
			netboxResponds500(w, r)
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}

	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Renew a token
	resp, err = tokenRenew(t, backend, storage, 42, "test", 0*time.Hour)
	assertFatal(t, resp, err, "unexpected status")

	// Assert our spy got hit and we got the correct ID and method
	assertEqual(t, 1, hits)
	assertEqual(t, "/api/users/tokens/42/", gotPath)
	assertEqual(t, "PATCH", gotMethod)
}

func TestSecretToken_RenewFatalWhenTokenNotFound(t *testing.T) {
	// Create backend handler we can watch
	var gotPath string
	var gotMethod string
	var hits int

	// Create custom handler to error after role setup
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/users/tokens/42/" && r.Method == "PATCH":
			hits++
			gotPath = r.URL.Path
			gotMethod = r.Method
			netboxResponds404(w, r)
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}

	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Write test role
	resp, err := roleCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Renew a token
	resp, err = tokenRenew(t, backend, storage, 42, "test", 0*time.Hour)
	assertFatalErr(t, resp, err, errTokenNotFound)

	// Assert our spy got hit and we got the correct ID and method
	assertEqual(t, 1, hits)
	assertEqual(t, "/api/users/tokens/42/", gotPath)
	assertEqual(t, "PATCH", gotMethod)
}

func TestSecretToken_RenewFatalWhenRoleNotFound(t *testing.T) {
	backend, storage := testBackend(t)
	resp, err := tokenRenew(t, backend, storage, 42, "test", 0)
	assertFatalErr(t, resp, err, errRoleNotFound)
}

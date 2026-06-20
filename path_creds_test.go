// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestCreds_ReadTokenOK_OldContract(t *testing.T) {
	tests := []struct {
		name          string
		roleData      map[string]any
		wantBody      map[string]any
		handlerReturn map[string]any
		netboxVersion string
	}{
		{
			name:          "unset version",
			roleData:      map[string]any{"username": "test"},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": false},
			handlerReturn: map[string]any{"id": 84},
			netboxVersion: "4.4.0",
		},
		{
			name:          "allowed ips",
			roleData:      map[string]any{"username": "test", "allowed_ips": []any{"1.1.1.1/32", "10.0.0.0/24"}},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": false, "allowed_ips": []any{"1.1.1.1/32", "10.0.0.0/24"}},
			handlerReturn: map[string]any{"id": 84},
			netboxVersion: "4.4.0",
		},
		{
			name:          "write enabled",
			roleData:      map[string]any{"username": "test", "write_enabled": true},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": true},
			handlerReturn: map[string]any{"id": 84},
			netboxVersion: "4.4.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mint the token
			resp, gotBody := mintToken(t, tt.netboxVersion, tt.roleData, tt.handlerReturn)

			// assert we sent an "old contract" request
			assertPresent(t, gotBody, "key")
			assertMissing(t, gotBody, "version")
			assertMissing(t, gotBody, "token")

			// assert the token we sent is the one we received
			assertEqual(t, gotBody["key"], resp.Data["token"].(string))
			delete(gotBody, "key")

			// We aren't testing the expire time
			delete(gotBody, "expires")

			// Assert the description
			assertDescription(t, "test", gotBody)
			delete(gotBody, "description")

			// Assert rest of the request body matches expected
			assertEqual(t, tt.wantBody, gotBody)

			// Assert we got the token ID
			assertEqual(t, tt.handlerReturn["id"].(int), resp.Secret.InternalData["token_id"])
		})
	}
}

func TestCreds_ValidateExpireTime(t *testing.T) {
	tests := []struct {
		name             string
		roleData         map[string]any
		handlerReturn    map[string]any
		wantEffectiveTTL time.Duration
	}{
		{
			name:             "default ttl",
			roleData:         map[string]any{"username": "test"},
			handlerReturn:    map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
			wantEffectiveTTL: 24 * time.Hour,
		},
		{
			name:             "ttl no max",
			roleData:         map[string]any{"username": "test", "ttl": time.Hour},
			handlerReturn:    map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
			wantEffectiveTTL: time.Hour,
		},
		{
			name:             "ttl over max",
			roleData:         map[string]any{"username": "test", "ttl": time.Hour, "max_ttl": 30 * time.Minute},
			handlerReturn:    map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
			wantEffectiveTTL: 30 * time.Minute,
		},
		{
			name:             "only max ttl",
			roleData:         map[string]any{"username": "test", "max_ttl": 30 * time.Minute},
			handlerReturn:    map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
			wantEffectiveTTL: 30 * time.Minute,
		},
		{
			name:             "ttl over system max",
			roleData:         map[string]any{"username": "test", "ttl": 300 * time.Hour},
			handlerReturn:    map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
			wantEffectiveTTL: 48 * time.Hour,
		},
		{
			name:             "ttl over system max with good role max",
			roleData:         map[string]any{"username": "test", "ttl": 300 * time.Hour, "max_ttl": 36 * time.Hour},
			handlerReturn:    map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
			wantEffectiveTTL: 36 * time.Hour,
		},
		{
			name:             "ttl over system max with bad role max",
			roleData:         map[string]any{"username": "test", "ttl": 300 * time.Hour, "max_ttl": 100 * time.Hour},
			handlerReturn:    map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
			wantEffectiveTTL: 48 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mint the token
			_, gotBody := mintToken(t, "4.4.0", tt.roleData, tt.handlerReturn)

			// Assert the token expire time
			assertExpireTime(t, gotBody, tt.wantEffectiveTTL)
		})
	}
}

func TestCreds_ReadErrorForUnknownRole(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxNoUsers)

	// Read token from test role
	resp, err := tokenRead(t, backend, storage, "test")

	// Assert that the error mentions role
	assertError(t, resp, err, "role")
}

func TestCreds_ReadFatalWhenNotConfigured(t *testing.T) {
	// Create mock backend without configuration
	backend, storage := testBackend(t)

	// Write test role
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test"})
	assertOK(t, resp, err)

	// Read token from test role
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert the read was fatal because the role was not configured
	// TODO: replace this with a sentinel error
	assertFatal(t, resp, err, "not configured")
}

func TestCreds_ReadFatalWhenNetboxUnreachable(t *testing.T) {
	// Create mock backend
	backend, storage, srv := testBackendWithNetbox(t, netboxUserFound)

	// Write test role
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test"})
	assertOK(t, resp, err)

	// Shut down netbox
	srv.Close()

	// Read token from test role
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert the read was fatable because netbox was unreachable
	assertFatal(t, resp, err, "request failure")
}

func TestCreds_ReadFatalWhenNetboxErrors(t *testing.T) {
	// Create custom handler to error after role setup
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users/tokens/" && r.Method == "POST":
			netboxResponds500(w, r)
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		}
	}

	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Write test role
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test"})
	assertOK(t, resp, err)

	// Read token from test role
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert the read was fatal due to an unexpected status code
	assertFatalErr(t, resp, err, errUnexpectedStatus)
}

func TestCreds_ReadFatalWhenUserDeleted(t *testing.T) {
	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, netboxNoUsers)

	// Write test role
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test"})
	assertOK(t, resp, err)

	// Read token from test role
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert the read was fatal because the user was not found
	assertFatalErr(t, resp, err, errUserNotFound)
}

// mintToken runs a happy path test from end to end.
// Used as a helper function in many other tests.
func mintToken(t *testing.T, netboxVersion string, roleData map[string]any, handlerReturn map[string]any) (*logical.Response, map[string]any) {
	// Create backend handler we can watch
	// we will assert these after the request
	var tokenHits int
	var gotBody map[string]any

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users/tokens/" && r.Method == "POST":
			// bump our counter to assert later
			tokenHits++

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
			json.NewEncoder(w).Encode(handlerReturn)

		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/status/" && r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]any{"netbox-version": netboxVersion})
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}

	// Create mock backend
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Write test role
	resp, err := roleCreate(t, backend, storage, "test", roleData)
	assertOK(t, resp, err)

	// Read token from test role
	resp, err = tokenRead(t, backend, storage, "test")
	assertOK(t, resp, err)

	// Assert the http handler was hit correctly
	assertEqual(t, 1, tokenHits)

	return resp, gotBody
}

func TestCreds_ReadFatalWhenVersionUndetectable(t *testing.T) {
	// Mock netbox server that returns an invalid response for the status endpoint
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/status/" && r.Method == "GET":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{}`))
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Create our test role
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test"})
	assertOK(t, resp, err)

	// Read a token
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert the read was fatal because we couldn't detect the API contract
	assertFatalErr(t, resp, err, errUnknownContract)
}

func TestCreds_NewContract_V1_SendsToken(t *testing.T) {
	// Request an explicit v1 token against a new contract server
	roleData := map[string]any{"username": "test", "version": 1}
	handlerReturn := map[string]any{"id": 84}
	resp, gotBody := mintToken(t, "4.5.0", roleData, handlerReturn)

	// Assert that we sent a "new contract" version 1 request
	assertEqual(t, float64(1), gotBody["version"])
	assertEqual(t, gotBody["token"], resp.Data["token"])
	assertMissing(t, gotBody, "key")
}

func TestCreds_UnsetVersion_V1OnNewContract(t *testing.T) {
	// Request a token with no version set against a new contract server
	roleData := map[string]any{"username": "test"}
	handlerReturn := map[string]any{"id": 84}
	resp, gotBody := mintToken(t, "4.5.0", roleData, handlerReturn)

	// same assertions as TestCreds_NewContract_V1_SendsToken, but our request exercises the unset-defaults-to-v1 branch
	assertEqual(t, float64(1), gotBody["version"])
	assertEqual(t, gotBody["token"], resp.Data["token"])
	assertMissing(t, gotBody, "key")
}

func TestCreds_NewContract_V2(t *testing.T) {
	// Request a v2 token against a v2 capable server
	roleData := map[string]any{"username": "test", "version": 2}
	handlerReturn := map[string]any{"id": 84, "key": "abc123", "token": "deadbeef"}
	resp, gotBody := mintToken(t, "4.6.2", roleData, handlerReturn)

	// Assert that we sent a v2 request
	assertEqual(t, float64(2), gotBody["version"])
	assertMissing(t, gotBody, "key")
	assertMissing(t, gotBody, "token")

	// Assert that we received the token that we expected
	assertEqual(t, "nbt_abc123.deadbeef", resp.Data["token"])
}

func TestCreds_V2_FatalBelow461(t *testing.T) {
	// Set up a 4.6.0 mock server
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/status/":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"netbox-version": "4.6.0"}`))
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/users/tokens/" && r.Method == "POST":
			t.Errorf("must not POST a token when v2 is unsupported by the server")
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Create a role that explicitly wants a v2 token
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test", "version": 2})
	assertOK(t, resp, err)

	// Read a token
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert that the read failed due to v2 not being supported
	assertFatalErr(t, resp, err, errV2Unsupported)
}

func TestCreds_V2_FatalOnOldContract(t *testing.T) {
	// Set up a 4.4.0 mock server that predates the new token contract
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/status/":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"netbox-version": "4.4.0"}`))
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/users/tokens/" && r.Method == "POST":
			t.Errorf("must not POST a token when v2 is unsupported by the server")
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Create a role that explicitly wants a v2 token
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test", "version": 2})
	assertOK(t, resp, err)

	// Read a token
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert that the read failed due to v2 not being supported
	assertFatalErr(t, resp, err, errV2Unsupported)
}

func TestCreds_V2_FatalWhenPepperMissing(t *testing.T) {
	// Set up a 4.6.2 mock server that doesn't have API_TOKEN_PEPERS configured
	var posted bool
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/status/":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"netbox-version": "4.6.2"}`))
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/users/tokens/" && r.Method == "POST":
			posted = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			w.Write([]byte(`{"error":"API_TOKEN_PEPPERS is not defined","exception":"ValueError"}`))
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Create a role that explicitly requests a v2 token
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test", "version": 2})
	assertOK(t, resp, err)

	// Read the token
	resp, err = tokenRead(t, backend, storage, "test")

	// Assert that the token read actually hit the api to generate the error
	assertEqual(t, true, posted)

	// Assert that the test failed due to peppers not being configured
	assertFatalErr(t, resp, err, errPepperNotConfigured)
}

func TestCreds_VersionRedetectedPerRequest(t *testing.T) {
	// Create a mock server that changes versions between requests
	var statusHits int
	var bodies []map[string]any

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/status/":
			statusHits++
			w.Header().Set("Content-Type", "application/json")
			// First mint sees an old server; second sees a new one.
			if statusHits == 1 {
				w.Write([]byte(`{"netbox-version": "4.4.0"}`))
			} else {
				w.Write([]byte(`{"netbox-version": "4.5.0"}`))
			}
		case r.URL.Path == "/api/users/users/" && r.Method == "GET":
			netboxUserFound(w, r)
		case r.URL.Path == "/api/users/tokens/" && r.Method == "POST":
			body := map[string]any{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("unparseable token request: %v", err)
			}
			bodies = append(bodies, body)
			// v1 never reads the secret back; only the token ID is consumed.
			json.NewEncoder(w).Encode(map[string]any{"id": 84})
		default:
			t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
		}
	}
	backend, storage, _ := testBackendWithNetbox(t, handler)

	// Create a role with an implicit version
	resp, err := roleCreate(t, backend, storage, "test", map[string]any{"username": "test"})
	assertOK(t, resp, err)

	// Read two tokens
	resp, err = tokenRead(t, backend, storage, "test")
	assertOK(t, resp, err)
	resp, err = tokenRead(t, backend, storage, "test")
	assertOK(t, resp, err)

	// Assert the version was re-detected on each read, not cached on the client
	assertEqual(t, 2, statusHits)

	// Assert that we got two token API hits
	assertEqual(t, 2, len(bodies))

	// Assert that the first request had an "old contract" request shape
	assertPresent(t, bodies[0], "key")
	assertMissing(t, bodies[0], "version")
	assertMissing(t, bodies[0], "token")

	// Assert that the second request upgraded to "new contract" v1 request
	assertEqual(t, float64(1), bodies[1]["version"])
	assertMissing(t, bodies[1], "key")
	assertPresent(t, bodies[1], "token")
}

package secretengine

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestCreds_ReadTokenOK(t *testing.T) {
	tests := []struct {
		name          string
		roleData      map[string]any
		wantBody      map[string]any
		handlerReturn map[string]any
	}{
		{
			name:          "auto version",
			roleData:      map[string]any{"username": "test"},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": false},
			handlerReturn: map[string]any{"id": 84},
		},
		{
			name:          "forced v1",
			roleData:      map[string]any{"username": "test", "version": 1},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": false, "version": float64(1)},
			handlerReturn: map[string]any{"id": 84},
		},
		{
			name:          "allowed ips",
			roleData:      map[string]any{"username": "test", "allowed_ips": []any{"1.1.1.1/32", "10.0.0.0/24"}},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": false, "allowed_ips": []any{"1.1.1.1/32", "10.0.0.0/24"}},
			handlerReturn: map[string]any{"id": 84},
		},
		{
			name:          "write enabled",
			roleData:      map[string]any{"username": "test", "write_enabled": true},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": true},
			handlerReturn: map[string]any{"id": 84},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mint the token
			resp, gotBody := mintToken(t, tt.roleData, tt.handlerReturn)

			// v1 tokens are created by us and sent to netbox
			//   so we assert that the token sent to netbox was also sent to the client
			// TODO: refactor to test the v2 shape
			sentKey, ok := gotBody["key"].(string)
			if !ok {
				t.Fatalf("key not sent to netbox")
			}
			assertEqual(t, sentKey, resp.Data["token"].(string))
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
			_, gotBody := mintToken(t, tt.roleData, tt.handlerReturn)

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
	assertFatalErr(t, resp, err, errUserNotFound)
}

func mintToken(t *testing.T, roleData map[string]any, handlerReturn map[string]any) (*logical.Response, map[string]any) {
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

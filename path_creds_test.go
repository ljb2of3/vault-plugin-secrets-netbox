package secretengine

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestCreds_ReadTokenOK(t *testing.T) {
	tests := []struct {
		name          string
		roleData      map[string]any
		wantBody      map[string]any
		handlerReturn map[string]any
	}{
		{
			name:          "basic v1",
			roleData:      map[string]any{"username": "test"},
			wantBody:      map[string]any{"user": float64(42), "write_enabled": false},
			handlerReturn: map[string]any{"id": 84, "key": "9fc9b897abec9ada2da6aec9dbc34596293c9cb9"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
					json.NewEncoder(w).Encode(tt.handlerReturn)
				case r.URL.Path == "/api/users/users/" && r.Method == "GET":
					netboxUserFound(w, r)
				default:
					t.Errorf("Unexpected HTTP call %s %s", r.Method, r.URL.Path)
				}
			}

			// Create mock backend
			backend, storage, _ := testBackendWithNetbox(t, handler)

			// Write test role
			resp, err := roleCreate(t, backend, storage, "test", tt.roleData)
			assertOK(t, resp, err)

			// Read token from test role
			resp, err = tokenRead(t, backend, storage, "test")
			assertOK(t, resp, err)

			// Assert the http handler was hit correctly
			assertEqual(t, 1, tokenHits)

			// Assert the token expire time
			ttl, _ := tt.roleData["ttl"].(time.Duration)
			assertExpireTime(t, gotBody, ttl)
			delete(gotBody, "expires")

			// Assert request body matches expected
			assertEqual(t, tt.wantBody, gotBody)

			// Assert we got the token we expected
			assertEqual(t, tt.handlerReturn["key"].(string), resp.Data["token"].(string))

			// Assert we got the token ID
			assertEqual(t, tt.handlerReturn["id"].(int), resp.Secret.InternalData["token_id"])
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
	t.Skip("not implemented")
}

func TestCreds_ReadFatalWhenNetboxUnreachable(t *testing.T) {
	t.Skip("not implemented")
}

func TestCreds_ReadFatalWhenNetboxErrors(t *testing.T) {
	t.Skip("not implemented")
}

func TestCreds_ReadFatalWhenUserDeleted(t *testing.T) {
	t.Skip("not implemented")
}

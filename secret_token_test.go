package secretengine

import (
	"net/http"
	"testing"
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
	assertFatal(t, resp, err)
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
	assertFatal(t, resp, err)

	// Assert our spy got hit and we got the correct ID and method
	assertEqual(t, 1, hits)
	assertEqual(t, "/api/users/tokens/42/", gotPath)
	assertEqual(t, "DELETE", gotMethod)
}

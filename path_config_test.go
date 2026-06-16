// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_CreateOKSetsFields(t *testing.T) {
	tests := []struct {
		name   string
		create map[string]any
	}{
		{
			name:   "url and token",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
		},
		{
			name:   "insecure",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "insecure": true},
		},
		{
			name:   "ca_cert",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "ca_cert": "test-cert"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, storage := testBackend(t)

			// Write test data
			resp, err := configCreate(t, backend, storage, tt.create)
			assertOK(t, resp, err)

			// Did our token actually get set?
			cfg, err := getConfig(t.Context(), storage)
			if err != nil {
				t.Fatalf("getClient() returned err: %v", err)
			}
			if cfg.Token != tt.create["token"] {
				t.Fatalf(`CREATE /config didn't set token. Wanted %v, got %v`, tt.create["token"], cfg.Token)
			}

			// Read it back
			resp, err = configRead(t, backend, storage)
			assertOK(t, resp, err)

			// Now the REAL tests...

			// Did we NOT get back a token?
			if _, ok := resp.Data["token"]; ok {
				t.Fatalf(`READ /config leaked a "token" field; it must be omitted entirely`)
			}

			// Did we get back what we wrote?
			// Required fields
			if resp.Data["url"] != tt.create["url"] {
				t.Fatalf(`READ /config "url" validation failed, want: %s got %s`, tt.create["url"], resp.Data["url"])
			}

			// Loop over optional fields
			for _, i := range []string{"insecure", "ca_cert"} {
				if _, ok := tt.create[i]; ok {
					if _, ok = resp.Data[i]; ok {
						if tt.create[i] != resp.Data[i] {
							t.Errorf(`READ /config "%v" validation failed: wanted %v got %v`, i, tt.create[i], resp.Data[i])
						}
					} else {
						t.Errorf(`READ /config "%s" validation failed: field not found`, i)
					}
				}
			}
		})
	}

}

func TestConfig_UpdateOKSetsFields(t *testing.T) {
	tests := []struct {
		name   string
		create map[string]any
		update map[string]any
	}{
		{
			name:   "url",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
			update: map[string]any{"url": "https://nb.foo.net"},
		},
		{
			name:   "token",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
			update: map[string]any{"token": "different"},
		},
		{
			name:   "insecure",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
			update: map[string]any{"insecure": true},
		},
		{
			name:   "insecure true then false",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "insecure": true},
			update: map[string]any{"insecure": false},
		},
		{
			name:   "ca_cert",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
			update: map[string]any{"ca_cert": "different-cert"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock backend
			backend, storage := testBackend(t)

			// Write test data
			resp, err := configCreate(t, backend, storage, tt.create)
			assertOK(t, resp, err)

			// Do an update
			resp, err = configUpdate(t, backend, storage, tt.update)
			assertOK(t, resp, err)

			// Did our token actually get updated?
			cfg, err := getConfig(t.Context(), storage)
			if err != nil {
				t.Fatalf("getClient() returned err: %v", err)
			}
			if _, ok := tt.update["token"]; ok {
				if cfg.Token != tt.update["token"] {
					t.Fatalf(`UPDATE /config didn't set token. Wanted %v, got %v`, tt.update["token"], cfg.Token)
				}
			} else {
				if cfg.Token != tt.create["token"] {
					t.Fatalf(`UPDATE /config unexpectedly changed token. Wanted %v, got %v`, tt.create["token"], cfg.Token)
				}
			}

			// Read it back
			resp, err = configRead(t, backend, storage)
			assertOK(t, resp, err)

			// Now the REAL tests...

			// Loop over all fields
			for _, i := range []string{"url", "insecure", "ca_cert"} {
				if _, ok := tt.update[i]; ok { // if it's in the update list, check that value
					if _, ok = resp.Data[i]; ok {
						if tt.update[i] != resp.Data[i] {
							t.Errorf(`READ /config "%v" update validation failed: wanted %v got %v`, i, tt.update[i], resp.Data[i])
						}
					} else {
						t.Errorf(`READ /config "%s" update validation failed: field not found`, i)
					}
				} else if _, ok := tt.create[i]; ok { // if it's not in the update list, is it in the create list?
					if _, ok = resp.Data[i]; ok {
						if tt.create[i] != resp.Data[i] {
							t.Errorf(`READ /config "%v" create validation failed: wanted %v got %v`, i, tt.create[i], resp.Data[i])
						}
					} else {
						t.Errorf(`READ /config "%s" create validation failed: field not found`, i)
					}
				}
			}
		})
	}

}

// Ensures we error if a URL isn't set
func TestConfig_CreateErrorForMissingURL(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Write with missing URL
	resp, err := configCreate(t, backend, storage, map[string]any{"token": "secret"})

	// Assert error message mentions url
	assertError(t, resp, err, "url")
}

// Ensures we error if a token isn't set
func TestConfig_CreateErrorForMissingToken(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Write with missing token
	resp, err := configCreate(t, backend, storage, map[string]any{"url": "https://nb.example.com"})

	// Assert error message mentions token
	assertError(t, resp, err, "token")
}

func TestConfig_CreateOKSetsDefaults(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Write config
	resp, err := configCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Read it back
	resp, err = configRead(t, backend, storage)
	assertOK(t, resp, err)

	// Assert defaults were set
	assertDefault(t, resp, "insecure", false)
	assertDefault(t, resp, "ca_cert", "")
}

func TestConfig_ReadAfterDeleteReturnsNil(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Write config
	resp, err := configCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Delete config
	resp, err = configDelete(t, backend, storage)
	assertOK(t, resp, err)

	// Read config
	resp, err = configRead(t, backend, storage)
	assertOK(t, resp, err)

	// Assert we got got nil
	if resp != nil {
		t.Fatalf(`READ /config after DELETE returned data`)
	}
}

func TestConfig_DeleteResetsClient(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Write config
	resp, err := configCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Warm the cache
	client, err := backend.getClient(t.Context(), storage)
	if err != nil {
		t.Fatalf("getClient() returned an error: %v", err)
	}

	if client == nil {
		t.Fatalf("getClient() did not return a client")
	}

	// Delete config
	resp, err = configDelete(t, backend, storage)
	assertOK(t, resp, err)

	// Verify the client was reset
	client, err = backend.getClient(t.Context(), storage)
	if err == nil {
		t.Fatalf("getClient() did not return an error")
	}

	if client != nil {
		t.Fatalf("getClient() did not return nil")
	}
}

func TestConfig_DeleteIsIdempotent(t *testing.T) {
	// Create the mock backend
	backend, storage := testBackend(t)

	// Write config
	resp, err := configCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Delete config
	resp, err = configDelete(t, backend, storage)
	assertOK(t, resp, err)

	// Delete config again
	resp, err = configDelete(t, backend, storage)
	assertOK(t, resp, err)
}

func TestConfig_ReadReturnsNilWhenNotConfigured(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Read config
	resp, err := configRead(t, backend, storage)
	assertOK(t, resp, err)

	// Assert we got a nil response
	if resp != nil {
		t.Fatalf("READ /config returned data")
	}
}

func TestConfig_EnsureExistenceCheckWorks(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Assert that the config doesn't exist
	_, exists, err := backend.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: storage,
	})

	if err != nil {
		t.Fatalf("existence check returned err: %v", err)
	}

	if exists {
		t.Fatalf("config exists before create")
	}

	// Write config
	resp, err := configCreateDefault(t, backend, storage)
	assertOK(t, resp, err)

	// Assert that the config does exist
	_, exists, err = backend.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: storage,
	})

	if err != nil {
		t.Fatalf("existence check returned err: %v", err)
	}

	if !exists {
		t.Fatalf("config does not exist after create")
	}
}

func TestConfig_UpdateFatalWhenNotConfigured(t *testing.T) {
	// Create mock backend
	backend, storage := testBackend(t)

	// Update the config without creating it
	resp, err := configUpdate(t, backend, storage, map[string]any{})

	// Assert that this is fatal
	assertFatal(t, resp, err, "not found during update")
}

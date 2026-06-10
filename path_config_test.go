package secretengine

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_CreateSetsFields(t *testing.T) {
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
		{
			name:   "token_scheme to auto",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": "auto"},
		},
		{
			name:   "token_scheme to v1",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": "v1"},
		},
		{
			name:   "optional token_scheme to v2",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": "v2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := testBackend(t)

			// Write test data. Sucessful CREATEs apparently return nil,nil
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Data:      tt.create,
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("CREATE /config returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("CREATE /config returned 4xx error, %v", resp.Error())
			}

			// Did our token actually get set?
			cfg, err := getConfig(t.Context(), storage)
			if err != nil {
				t.Fatalf("getClient() returned err: %v", err)
			}
			if cfg.Token != tt.create["token"] {
				t.Fatalf(`CREATE /config didn't set token. Wanted %v, got %v`, tt.create["token"], cfg.Token)
			}

			// Read it back
			resp, err = b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "config",
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("READ /config returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("READ /config returned 4xx error, %v", resp.Error())
			}

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
			for _, i := range []string{"insecure", "ca_cert", "token_scheme"} {
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

func TestConfig_UpdateSetsFields(t *testing.T) {
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
			name:   "ca_cert",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
			update: map[string]any{"ca_cert": "different-cert"},
		},
		{
			name:   "token_scheme",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
			update: map[string]any{"token_scheme": "v2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := testBackend(t)

			// Write test data. Sucessful CREATEs apparently return nil,nil
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Data:      tt.create,
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("CREATE /config returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("CREATE /config returned 4xx error, %v", resp.Error())
			}

			// Do an update
			resp, err = b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config",
				Data:      tt.update,
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("UPDATE /config returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("UPDATE /config returned 4xx error, %v", resp.Error())
			}

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
			resp, err = b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "config",
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("READ /config returned err %v", err)
			}

			// 4xx error, bad user input
			if resp.IsError() {
				t.Fatalf("READ /config returned 4xx error, %v", resp.Error())
			}

			// Now the REAL tests...

			// Loop over all fields
			for _, i := range []string{"url", "insecure", "ca_cert", "token_scheme"} {
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
func TestConfig_CreateReturnsUserErrorForMissingURL(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"token": "secret"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We expect a response error
	if !resp.IsError() {
		t.Fatalf(`CREATE /config suceeded without "url"`)
	}
}

// Ensures we error if a token isn't set
func TestConfig_CreateReturnsUserErrorForMissingToken(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We expect a response error
	if !resp.IsError() {
		t.Fatalf(`CREATE /config suceeded without "token"`)
	}
}

// Ensures we error if we pass the wrong token value
func TestConfig_CreateReturnsUserErrorForInvalidTokenScheme(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": "v3"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We expect a response error
	if !resp.IsError() {
		t.Fatalf(`CREATE /config suceeded with incorrect "token_scheme: v3"`)
	}
}

func TestConfig_CreateSetsDefaults(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com", "token": "secret"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`CREATE /config failed with %v"`, resp.Error())
	}

	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("READ /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`READ /config failed with %v"`, resp.Error())
	}

	// Validate defaults
	if resp.Data["insecure"] != false {
		t.Fatalf(`CREATE /config didn't set default for "insecure": wanted false, got %v`, resp.Data["insecure"])
	}

	if resp.Data["ca_cert"] != "" {
		t.Fatalf(`CREATE /config didn't set default for "ca_cert": wanted , got %v`, resp.Data["ca_cert"])
	}

	if resp.Data["token_scheme"] != "auto" {
		t.Fatalf(`CREATE /config didn't set default for "token_scheme": wanted auto, got %v`, resp.Data["token_scheme"])
	}
}

func TestConfig_ReadAfterDeleteReturnsNil(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com", "token": "secret"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`CREATE /config failed with %v"`, resp.Error())
	}

	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("DELETE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`DELETE /config failed with %v"`, resp.Error())
	}

	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("READ /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`READ /config failed with %v"`, resp.Error())
	}

	if resp != nil {
		t.Fatalf(`READ /config after DELETE returned data`)
	}
}

func TestConfig_DeleteResetsClient(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com", "token": "secret"},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`CREATE /config failed with %v"`, resp.Error())
	}

	// Warm the cache
	client, err := b.getClient(t.Context(), storage)
	if err != nil {
		t.Fatalf("getClient() returned an error: %v", err)
	}

	if client == nil {
		t.Fatalf("getClient() did not return a client")
	}

	// Delete
	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("DELETE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`DELETE /config failed with %v"`, resp.Error())
	}

	// Verify the client was reset
	client, err = b.getClient(t.Context(), storage)
	if err == nil {
		t.Fatalf("getClient() did not return an error")
	}

	if client != nil {
		t.Fatalf("getClient() did not return nil")
	}
}

func TestConfig_DeleteIsIdempotent(t *testing.T) {
	b, storage := testBackend(t)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("DELETE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`DELETE /config failed with %v"`, resp.Error())
	}
}

func TestConfig_ReadReturnsNilWhenNotConfigured(t *testing.T) {
	b, storage := testBackend(t)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("READ /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`READ /config failed with %v"`, resp.Error())
	}

	if resp != nil {
		t.Fatalf("READ /config returned data")
	}
}

func TestConfig_CreateNormalizesTokenSchemeCase(t *testing.T) {
	tests := []struct {
		name string
		set  string
		want string
	}{
		{name: "auto", set: "AUTO", want: "auto"},
		{name: "v1", set: "V1", want: "v1"},
		{name: "v2", set: "V2", want: "v2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := testBackend(t)

			// Create with missing URL
			resp, err := b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "config",
				Data:      map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": tt.set},
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("CREATE /config returned err: %v", err)
			}

			// We don't expect a response error
			if resp.IsError() {
				t.Fatalf(`CREATE /config failed with %v"`, resp.Error())
			}

			resp, err = b.HandleRequest(t.Context(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "config",
				Storage:   storage,
			})

			// 5xx error, vault broke
			if err != nil {
				t.Fatalf("READ /config returned err: %v", err)
			}

			// We don't expect a response error
			if resp.IsError() {
				t.Fatalf(`READ /config failed with %v"`, resp.Error())
			}

			cfg, err := getConfig(t.Context(), storage)
			if err != nil {
				t.Fatalf("getClient() returned err: %v", err)
			}

			if cfg.TokenScheme != tt.want {
				t.Fatalf("Case not normalized: want %v got %v", tt.want, cfg.TokenScheme)
			}

		})
	}

}

func TestConfig_CreateEmptyTokenSchemeSetsAuto(t *testing.T) {

	b, storage := testBackend(t)

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": ""},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`CREATE /config failed with %v"`, resp.Error())
	}

	resp, err = b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("READ /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`READ /config failed with %v"`, resp.Error())
	}

	cfg, err := getConfig(t.Context(), storage)
	if err != nil {
		t.Fatalf("getClient() returned err: %v", err)
	}

	if cfg.TokenScheme != "auto" {
		t.Fatalf("Case not normalized: want auto got %v", cfg.TokenScheme)
	}
}

func TestConfig_EnsureExistenceCheckWorks(t *testing.T) {
	b, storage := testBackend(t)

	_, exists, err := b.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: storage,
	})

	if err != nil {
		t.Fatalf("existence check returned err: %v", err)
	}

	if exists {
		t.Fatalf("config exists before create")
	}

	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": ""},
		Storage:   storage,
	})

	// 5xx error, vault broke
	if err != nil {
		t.Fatalf("CREATE /config returned err: %v", err)
	}

	// We don't expect a response error
	if resp.IsError() {
		t.Fatalf(`CREATE /config failed with %v"`, resp.Error())
	}

	_, exists, err = b.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: storage,
	})

	if err != nil {
		t.Fatalf("existence check returned err: %v", err)
	}

	if !exists {
		t.Fatalf("config does not exist after create")
	}

}

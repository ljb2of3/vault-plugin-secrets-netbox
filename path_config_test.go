package secretengine

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_Create(t *testing.T) {
	tests := []struct {
		name   string
		create map[string]any
	}{
		{
			name:   "minimal",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret"},
		},
		{
			name:   "optional insecure true",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "insecure": true},
		},
		{
			name:   "optional insecure false",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "insecure": false},
		},
		{
			name:   "optional ca_cert",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "ca_cert": "test-cert"},
		},
		{
			name:   "optional token_scheme auto",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": "auto"},
		},
		{
			name:   "optional token_scheme v1",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": "v1"},
		},
		{
			name:   "optional token_scheme v2",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "token_scheme": "v2"},
		},
		{
			name:   "everything",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "insecure": true, "ca_cert": "asdf", "token_scheme": "v2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := testBackend(t)

			// Write test data. Sucessful CREATEs apparently return nil,nil
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
			cfg, _ := getConfig(context.Background(), storage)
			if cfg.Token != tt.create["token"] {
				t.Fatalf(`CREATE /config didn't set token. Wanted %v, got %v`, tt.create["token"], cfg.Token)
			}

			// Read it back
			resp, err = b.HandleRequest(context.Background(), &logical.Request{
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

func TestConfig_Update(t *testing.T) {
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
		{
			name:   "everything",
			create: map[string]any{"url": "https://nb.example.com", "token": "secret", "insecure": true, "ca_cert": "asdf", "token_scheme": "v2"},
			update: map[string]any{"url": "https://nb.local", "token": "different", "insecure": false, "ca_cert": "foobar", "token_scheme": "auto"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, storage := testBackend(t)

			// Write test data. Sucessful CREATEs apparently return nil,nil
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
			resp, err = b.HandleRequest(context.Background(), &logical.Request{
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
			cfg, _ := getConfig(context.Background(), storage)
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
			resp, err = b.HandleRequest(context.Background(), &logical.Request{
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
func TestConfig_MissingURL(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
func TestConfig_MissingToken(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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
func TestConfig_WrongTokenScheme(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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

func TestConfig_VerifyDefaults(t *testing.T) {
	b, storage := testBackend(t)

	// Create with missing URL
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
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

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
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

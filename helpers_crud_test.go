package secretengine

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// Creates the config
func configCreate(t *testing.T, b *netboxBackend, s logical.Storage, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      data,
		Storage:   s,
	})
}

// Updates the config
func configUpdate(t *testing.T, b *netboxBackend, s logical.Storage, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      data,
		Storage:   s,
	})
}

// Reads the config
func configRead(t *testing.T, b *netboxBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
}

// Deletes the config
func configDelete(t *testing.T, b *netboxBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   s,
	})
}

// Creates the config with default settings
func configCreateDefault(t *testing.T, b *netboxBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return configCreate(t, b, s, map[string]any{"url": "https://nb.example.com", "token": "secret"})
}

// Creates a role
func roleCreate(t *testing.T, b *netboxBackend, s logical.Storage, name string, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", name),
		Data:      data,
		Storage:   s,
	})
}

// Updates a role
func roleUpdate(t *testing.T, b *netboxBackend, s logical.Storage, name string, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s", name),
		Data:      data,
		Storage:   s,
	})
}

// Reads a role
func roleRead(t *testing.T, b *netboxBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", name),
		Storage:   s,
	})
}

// Deletes a role
func roleDelete(t *testing.T, b *netboxBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("role/%s", name),
		Storage:   s,
	})
}

// Lists roles
func roleList(t *testing.T, b *netboxBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   s,
	})
}

// Creates a role "test" with default values (username "test")
func roleCreateDefault(t *testing.T, b *netboxBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return roleCreate(t, b, s, "test", map[string]any{"username": "test"})
}

// Read a token
func tokenRead(t *testing.T, b *netboxBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("creds/%s", name),
		Storage:   s,
	})
}

// Revoke a token
func tokenRevoke(t *testing.T, b *netboxBackend, s logical.Storage, id int) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   s,
		Secret: &logical.Secret{
			InternalData: map[string]any{
				"secret_type": netboxTokenType,
				"token_id":    float64(id), // vault will internally pass a float64, so we type cast
			},
		},
	})
}

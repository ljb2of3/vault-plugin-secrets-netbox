package secretengine

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

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

// Creates a role "test" with default values (username "test")
func roleCreateDefault(t *testing.T, b *netboxBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return roleCreate(t, b, s, "test", map[string]any{"username": "test"})
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

func roleRead(t *testing.T, b *netboxBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", name),
		Storage:   s,
	})
}

func roleDelete(t *testing.T, b *netboxBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("role/%s", name),
		Storage:   s,
	})
}

func roleList(t *testing.T, b *netboxBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   s,
	})
}

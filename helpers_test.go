package secretengine

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(t *testing.T) (*netboxBackend, logical.Storage) {
	t.Helper()
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*netboxBackend), cfg.StorageView
}

package secretengine

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_RoundTrip(t *testing.T) {
	b, storage := testBackend(t)

	// Write test data. Sucessful CREATEs apparently return nil,nil
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]any{"url": "https://nb.example.com", "token": "secret"},
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

	// Did we get back what we wrote?
	if resp.Data["url"] != "https://nb.example.com" {
		t.Fatalf(`READ /config "url" validation failed, want: %s got %s`, "https://nb.example.com", resp.Data["url"])
	}

	// Did we NOT get back a token?
	if _, ok := resp.Data["token"]; ok {
		t.Fatalf(`READ /config leaked a "token" field; it must be omitted entirely`)
	}
}

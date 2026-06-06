package secretengine

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// This func sets up our backend and returns it to vault
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()

	err := b.Setup(ctx, conf)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// This is where the magic happens. This is the struct that Vault is interacting with
type netboxBackend struct {
	*framework.Backend // this comes from the vault sdk
	lock               sync.RWMutex
	client             *netboxClient // this is our code
}

// This func wires up our backend struct and provides config for our plugin
func backend() *netboxBackend {
	b := netboxBackend{}

	// framework.Backend comes from the vault sdk
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths:       framework.PathAppend(),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return &b
}

func (b *netboxBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *netboxBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// This is our plugin's help text
const backendHelp = `
The Netbox secrets backend dynamically generates API tokens. 
Use config/ to set the netbox url and admin credentials with permissions to generate tokens.
Then create a role/<name> to configure a username to generate a token for.
Call creds/<role> to generate a token.`

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

const rootHelp = `
The Netbox secrets backend dynamically generates API tokens. 
Use config/ to set the netbox url and admin credentials with permissions to generate tokens.
Then create a role/<name> to configure a username to generate a token for.
Call creds/<role> to generate a token.`

// This func wires up our backend struct and provides config for our plugin
func backend() *netboxBackend {
	b := netboxBackend{}

	// framework.Backend comes from the vault sdk
	b.Backend = &framework.Backend{
		// Help is the help text that is shown when a help request is made
		// on the root of this resource. The root help is special since we
		// show all the paths that can be requested.
		Help: strings.TrimSpace(rootHelp),

		// Paths are the various routes that the backend responds to.
		// This cannot be modified after construction (i.e. dynamically changing
		// paths, including adding or removing, is not allowed once the
		// backend is in use).
		//
		// PathsSpecial is the list of path patterns that denote the paths above
		// that require special privileges.
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
			},
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},

		// Secrets is the list of secret types that this backend can
		// return. It is used to automatically generate proper responses,
		// and ease specifying callbacks for revocation, renewal, etc.
		Secrets: []*framework.Secret{},

		// BackendType is the logical.BackendType for the backend implementation
		BackendType: logical.TypeLogical,

		// Invalidate is called when a key is modified, if required.
		Invalidate: b.invalidate,
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

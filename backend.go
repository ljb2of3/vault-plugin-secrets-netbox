// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

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
The NetBox secrets backend dynamically generates short-lived NetBox API tokens.

Getting started is a three step workflow:

  1. Configure the backend at config/ with the NetBox server URL and an admin
     API token that has permission to create and delete tokens.
  2. Define one or more roles at role/<name>, each mapping to a NetBox username
     along with the settings (TTL, write access, allowed IPs, token version)
     applied to tokens minted for that role.
  3. Read creds/<role> to mint a token. Vault leases the token and revokes it
     in NetBox when the lease expires or is revoked.

See the help for each path (e.g. "vault path-help <mount>/config") for details.`

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
				pathCreds(&b),
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
		Secrets: []*framework.Secret{
			b.netboxToken(),
		},

		// BackendType is the logical.BackendType for the backend implementation
		BackendType: logical.TypeLogical,

		// Invalidate is called when a key is modified, if required.
		Invalidate: b.invalidate,

		// RunningVersion reports the version string to the vault core
		RunningVersion: Version,
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

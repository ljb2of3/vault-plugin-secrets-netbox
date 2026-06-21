// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleStorageBase = "role/" // vault gives us a kv store, where are we storing our roles?
)

// the json blob that will be written to vault to store our role
type netboxRole struct {
	Username     string        `json:"username"`
	WriteEnabled bool          `json:"write_enabled"`
	AllowedIPs   []string      `json:"allowed_ips"`
	Version      int           `json:"version"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
}

// <mount>/role/*
const pathRoleHelpSynopsis = `
Configure netbox roles`

const pathRoleHelpDescription = `
Each role maps to a specific netbox username, and has various config options. 
Multiple roles may point at the same user with different settings.`

const pathRoleListHelpSynopsis = `
List netbox roles`

const pathRoleHelpListDescription = `
Lists all configured netbox roles`

func pathRole(b *netboxBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:     framework.TypeLowerCaseString,
					Required: true,
				},
				"username": {
					Type:        framework.TypeString,
					Description: "The netbox user assigned to the token minted.",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "username",
					},
				},
				"write_enabled": {
					Type:        framework.TypeBool,
					Description: "Minted token has write access.",
					Default:     false,
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Write Enabled",
					},
				},
				"allowed_ips": {
					Type:        framework.TypeCommaStringSlice,
					Description: "CIDR networks that are allowed to use minted token.",
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Allowed IPs",
					},
				},
				"version": {
					Type:        framework.TypeInt,
					Description: "Version of token to mint. Allowed values are 1 or 2",
					DisplayAttrs: &framework.DisplayAttributes{
						Name: "Version",
					},
					AllowedValues: []any{1, 2},
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
			},

			// Map CRUD operations to our functions
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},

			// func to check to see if the role exists
			ExistenceCheck: b.pathRoleExistenceCheck,

			// help text (defined in help_text.go)
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleHelpListDescription,
		},
	}
}

func getRole(ctx context.Context, s logical.Storage, name string) (*netboxRole, error) {
	// Fetch role (json) from vault storage
	entry, err := s.Get(ctx, roleStoragePath(name))

	// Error fetching from storage
	if err != nil {
		return nil, err
	}

	// No role
	if entry == nil {
		return nil, nil
	}

	// Create our struct, and decode the json
	role := new(netboxRole)

	err = entry.DecodeJSON(&role)
	if err != nil {
		return nil, fmt.Errorf("error reading role %q: %w", name, err)
	}

	// Migrate legacy version 0 to default version 1
	if role.Version == 0 {
		role.Version = 1
	}

	// Return the role
	return role, nil
}

func (b *netboxBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name, ok := data.GetOk("name")
	if !ok {
		return nil, errNameNotSet
	}

	role, err := getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username":      role.Username,
			"write_enabled": role.WriteEnabled,
			"allowed_ips":   role.AllowedIPs,
			"version":       role.Version,
			"ttl":           role.TTL.Seconds(),
			"max_ttl":       role.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *netboxBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var resp = &logical.Response{}
	var role *netboxRole
	var createMode bool

	name, ok := data.GetOk("name")
	if !ok {
		return nil, errNameNotSet
	}

	switch req.Operation {
	case logical.CreateOperation: // Create Op, make a blank role
		createMode = true
		role = new(netboxRole)
	case logical.UpdateOperation: // Update Op, load existing role
		createMode = false
		existing, err := getRole(ctx, req.Storage, name.(string))
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, fmt.Errorf("role %q not found during update operation", name)
		}
		role = existing
	default: // How did we end up here?
		return nil, errors.New("role write called on unsupported operation")
	}

	// Field: Username (required)
	// Only check that it's sent in create mode. Validation later
	if _, ok := data.GetOk("username"); !ok && createMode {
		return logical.ErrorResponse(`You must provide a username.`), nil
	}

	// Field: WriteEnabled (not required, set default)
	if writeEnabled, ok := data.GetOk("write_enabled"); ok {
		role.WriteEnabled = writeEnabled.(bool)
	} else if createMode {
		role.WriteEnabled = data.GetDefaultOrZero("write_enabled").(bool)
	}

	// Field: AllowedIPs (not required, set default)
	if allowedIPs, ok := data.GetOk("allowed_ips"); ok {
		role.AllowedIPs = []string{}
		// Validate IPs
		for _, x := range allowedIPs.([]string) {
			if err := validateAllowedIP(x); err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%v", err)), nil
			}
			role.AllowedIPs = append(role.AllowedIPs, x)
		}
	} else if createMode {
		role.AllowedIPs = []string{}
	}

	// Field: Version (not required, set default)
	if version, ok := data.GetOk("version"); ok {
		switch version.(int) {
		case 1:
			role.Version = 1
		case 2:
			role.Version = 2
		default:
			return logical.ErrorResponse("version must be 1 or 2"), nil
		}
	} else if createMode {
		role.Version = 1
	}

	// Field: TTL (not required, set default)
	if ttl, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttl.(int)) * time.Second
	} else if createMode {
		role.TTL = 0 * time.Second
	}

	// Field: Max TTL (not required, set default)
	if maxTTL, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	} else if createMode {
		role.MaxTTL = 0 * time.Second
	}

	// Field: Username (required)
	// Existence check on create happened earlier
	if username, ok := data.GetOk("username"); ok {
		// Closure to capture multiple errors for one switch below
		err := func() error {
			c, err := b.getClient(ctx, req.Storage)
			if err != nil {
				return err
			}
			_, err = c.resolveUserID(ctx, username.(string))
			return err
		}()
		if err != nil {
			switch {
			case errors.Is(err, errNetboxNotConfigured):
				resp.AddWarning("Netbox backend not configured. Be sure to write to /config before minting tokens.")
			case errors.Is(err, errRequestFailure):
				resp.AddWarning(fmt.Sprintf("Unable to validate username because netbox was unreachable: %v", err))
			case errors.Is(err, errUserNotFound):
				resp.AddWarning(fmt.Sprintf("%q not a valid netbox user. Create netbox user before minting tokens.", username.(string)))
			default:
				return nil, err
			}
		}
		role.Username = username.(string)
	}

	entry, err := logical.StorageEntryJSON(roleStoragePath(name), role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *netboxBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name, ok := data.GetOk("name")
	if !ok {
		return nil, errNameNotSet
	}

	err := req.Storage.Delete(ctx, roleStoragePath(name))

	return nil, err
}

// pathRoleExistenceCheck verifies if the role exists.
func (b *netboxBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name, ok := data.GetOk("name")
	if !ok {
		return false, errNameNotSet
	}

	out, err := req.Storage.Get(ctx, roleStoragePath(name))
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *netboxBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleStorageBase)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func validateAllowedIP(input string) error {
	ip, network, err := net.ParseCIDR(input)

	if err != nil {
		return err
	}

	if !network.IP.Equal(ip) {
		return fmt.Errorf("%q: %w", input, errHostBitsSet)
	}

	return nil
}

func roleStoragePath(name any) string {
	return roleStorageBase + name.(string)
}

var errHostBitsSet = errors.New("network contains host bits")
var errNameNotSet = errors.New("name not set")

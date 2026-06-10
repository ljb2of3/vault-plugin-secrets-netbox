package secretengine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config" // vault gives us a kv store, where are we storing our config?
)

// the json blob that will be written to vault to store our configuration
type netboxConfig struct {
	URL         string `json:"url"`
	Token       string `json:"token"`
	InsecureTLS bool   `json:"insecure"`
	CACert      string `json:"ca_cert"`
	TokenScheme string `json:"token_scheme"`
}

// pathConfig extends the Vault API with a `/config` endpoint for this backend
func pathConfig(b *netboxBackend) *framework.Path {
	return &framework.Path{
		// What path are we defining?
		Pattern: "config",

		// What fields can we set on this path?
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Description: "The URL for the Netbox server",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "URL",
					Sensitive: false,
				},
			},
			"token": {
				Type:        framework.TypeString,
				Description: "The token used to access Netbox",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Token",
					Sensitive: true,
				},
			},
			"insecure": {
				Type:        framework.TypeBool,
				Description: "Disable validation of the Netbox server's TLS certificate",
				Required:    false,
				Default:     false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Insecure TLS",
					Sensitive: false,
				},
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "CA certifcate that signed the Netbox server's cert",
				Required:    false,
				Default:     "",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "CA Certificate",
					Sensitive: false,
				},
			},
			"token_scheme": {
				Type:        framework.TypeString,
				Description: "Netbox token scheme (auto, v1, v2)",
				Required:    false,
				Default:     "auto",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Token Scheme",
					Sensitive: false,
				},
				AllowedValues: []interface{}{"auto", "v1", "v2"},
			},
		},

		// Map CRUD operations to our functions
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},

		// func to check to see if the config exists
		ExistenceCheck: b.pathConfigExistenceCheck,

		// help text (defined in help_text.go)
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *netboxBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *netboxBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"url":          config.URL,
			"insecure":     config.InsecureTLS,
			"ca_cert":      config.CACert,
			"token_scheme": config.TokenScheme,
		},
	}, nil
}

// pathConfigWrite updates the configuration for the backend
func (b *netboxBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	var config *netboxConfig
	var createMode bool

	switch req.Operation {
	case logical.CreateOperation: // Create Op, make a blank config
		createMode = true
		config = new(netboxConfig)
	case logical.UpdateOperation: // Update Op, load existing config
		createMode = false
		existing, err := getConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, errors.New("config not found during update operation")
		}
		config = existing
	default: // How did we end up here?
		return nil, errors.New("config write called on unsupported operation")
	}

	// Field: URL (required)
	if baseURL, ok := data.GetOk("url"); ok {
		config.URL = baseURL.(string)
	} else if createMode {
		return logical.ErrorResponse(`You must provide a url.`), nil
	}

	// Field: Token (required)
	if token, ok := data.GetOk("token"); ok {
		config.Token = token.(string)
	} else if createMode {
		return logical.ErrorResponse(`You must provide a token.`), nil
	}

	// Field: InsecureTLS (not required, set default)
	if insecure, ok := data.GetOk("insecure"); ok {
		config.InsecureTLS = insecure.(bool)
	} else if createMode {
		config.InsecureTLS = data.GetDefaultOrZero("insecure").(bool)
	}

	// Field: CACert (not required, set default)
	if cacert, ok := data.GetOk("ca_cert"); ok {
		config.CACert = cacert.(string)
	} else if createMode {
		config.CACert = data.GetDefaultOrZero("ca_cert").(string)
	}

	// Field: TokenScheme (not required, set default)
	if tokenScheme, ok := data.GetOk("token_scheme"); ok {
		lowerScheme := strings.ToLower(tokenScheme.(string))
		if lowerScheme == "" {
			config.TokenScheme = data.GetDefaultOrZero("token_scheme").(string)
		} else {
			switch lowerScheme {
			case "auto", "v1", "v2":
				config.TokenScheme = lowerScheme
			default:
				return logical.ErrorResponse("Invalid token_scheme: %v. Must be one of: auto, v1, v2", tokenScheme.(string)), nil
			}
		}
	} else if createMode {
		config.TokenScheme = data.GetDefaultOrZero("token_scheme").(string)
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

// pathConfigDelete removes the configuration for the backend
func (b *netboxBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

// Reads our configuration from vault's storage
func getConfig(ctx context.Context, s logical.Storage) (*netboxConfig, error) {

	// Fetch config (json) from vault storage
	entry, err := s.Get(ctx, configStoragePath)

	// Error fetching from storage
	if err != nil {
		return nil, err
	}

	// No config
	if entry == nil {
		return nil, nil
	}

	// Create our struct, and decode the json
	config := new(netboxConfig)

	err = entry.DecodeJSON(&config)
	if err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// treat empty string on TokenScheme as auto
	if config.TokenScheme == "" {
		config.TokenScheme = "auto"
	}

	// Return the config
	return config, nil
}

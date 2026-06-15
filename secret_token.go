package secretengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const netboxTokenType = "netbox_token"

func (b *netboxBackend) netboxToken() *framework.Secret {
	return &framework.Secret{
		Type: netboxTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Netbox Token",
			},
		},
		Revoke: b.revokeToken,
	}
}

func (b *netboxBackend) revokeToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the token id from internal data
	raw, ok := req.Secret.InternalData["token_id"]
	if !ok {
		return nil, errors.New("token_id not set")
	}

	// cast it to the correct type
	token_id := int(raw.(float64))

	// build the path to delete
	path := fmt.Sprintf("/api/users/tokens/%d/", token_id)

	// Grab our netbox client
	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Fire off request to netbox
	resp, err := c.rawRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return nil, err
	}

	// Drain the body
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Check the return code and respond
	switch {
	case resp.StatusCode == 404:
		return nil, nil // already gone
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return nil, nil // deleted
	default:
		return nil, fmt.Errorf("%w: %d %s", errUnexpectedStatus, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

}

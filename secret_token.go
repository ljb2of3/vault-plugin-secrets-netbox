// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

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
				Description: "The generated NetBox API token.",
			},
		},
		Revoke: b.revokeToken,
		Renew:  b.renewToken,
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
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

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

func (b *netboxBackend) renewToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the token id from internal data
	raw, ok := req.Secret.InternalData["token_id"]
	if !ok {
		return nil, errors.New("token_id not set")
	}

	// cast it to the correct type
	token_id := int(raw.(float64))

	// build the path to update
	path := fmt.Sprintf("/api/users/tokens/%d/", token_id)

	// We also need the role to know TTL / Max TTL
	name, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("role not set")
	}

	// Fetch the role from storage
	role, err := getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	// Role not found?
	if role == nil {
		return nil, errRoleNotFound
	}

	// Compute expire time
	ttl, _, err := framework.CalculateTTL(
		b.System(),           // sysView — gives DefaultLeaseTTL/MaxLeaseTTL (mount-aware)
		req.Secret.Increment, // increment — renewal-only, 0 at issue
		role.TTL,             // backendTTL — your requested ttl (0 → falls to DefaultLeaseTTL)
		0,                    // period — periodic auth only, N/A for secrets
		role.MaxTTL,          // backendMaxTTL — role's cap (0 → no extra cap)
		0,                    // explicitMaxTTL — not using
		req.Secret.IssueTime, // startTime
	)
	if err != nil {
		return nil, err
	}

	expires := time.Now().Add(ttl).Add(netboxGracePeriod)

	// Grab our netbox client
	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	tokenRequest := netboxTokenUpdateRequest{
		Expires: expires.Format(time.RFC3339),
	}

	// Fire off request to netbox
	resp, err := c.rawRequest(ctx, "PATCH", path, tokenRequest)
	if err != nil {
		return nil, err
	}

	// Drain the body
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Check the return code and respond
	switch {
	case resp.StatusCode == 404:
		return nil, errTokenNotFound // already gone
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		vaultResp := &logical.Response{Secret: req.Secret}
		vaultResp.Secret.TTL = role.TTL
		vaultResp.Secret.MaxTTL = role.MaxTTL
		return vaultResp, nil
	default:
		return nil, fmt.Errorf("%w: %d %s", errUnexpectedStatus, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

type netboxTokenUpdateRequest struct {
	Expires string `json:"expires"`
}

var (
	errTokenNotFound = errors.New("token not found")
	errRoleNotFound  = errors.New("role not found")
)

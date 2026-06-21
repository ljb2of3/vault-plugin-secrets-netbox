// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package secretengine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const netboxGracePeriod = 5 * time.Minute

const pathCredsHelpSynopsis = `Mints a netbox token`
const pathCredsListDescription = `Mints a netbox token`

type netboxTokenRequest struct {
	User         int      `json:"user"`
	Expires      string   `json:"expires"`
	WriteEnabled bool     `json:"write_enabled"`
	Description  string   `json:"description"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	Version      int      `json:"version,omitempty"`
	Key          string   `json:"key,omitempty"`
	Token        string   `json:"token,omitempty"`
}

type netboxTokenResponse struct {
	ID    int    `json:"id"`
	Key   string `json:"key"`
	Token string `json:"token"`
}

func pathCreds(b *netboxBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:     framework.TypeLowerCaseString,
				Required: true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredsRead,
			},
		},
		HelpSynopsis:    pathCredsHelpSynopsis,
		HelpDescription: pathCredsListDescription,
	}
}

func (b *netboxBackend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// What role are we looking for?
	name, ok := data.GetOk("name")
	if !ok {
		return nil, errNameNotSet
	}

	// Fetch the role from storage
	role, err := getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	// Role not found?
	if role == nil {
		return logical.ErrorResponse("Role %q not found", name), nil
	}

	// Grab our netbox client
	c, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Fetch the user ID from netbox
	userID, err := c.resolveUserID(ctx, role.Username)
	if err != nil {
		return nil, err
	}

	// Compute expire time
	ttl, _, err := framework.CalculateTTL(
		b.System(),  // sysView — gives DefaultLeaseTTL/MaxLeaseTTL (mount-aware)
		0,           // increment — renewal-only, 0 at issue
		role.TTL,    // backendTTL — your requested ttl (0 → falls to DefaultLeaseTTL)
		0,           // period — periodic auth only, N/A for secrets
		role.MaxTTL, // backendMaxTTL — role's cap (0 → no extra cap)
		0,           // explicitMaxTTL — not using
		time.Time{}, // startTime — zero means "now"
	)
	if err != nil {
		return nil, err
	}

	expires := time.Now().Add(ttl).Add(netboxGracePeriod)

	// Compute description
	description := fmt.Sprintf("vault: role=%s req=%s", name, req.ID)

	// Fill out request struct
	tokenRequest := netboxTokenRequest{
		User:         userID,
		Expires:      expires.Format(time.RFC3339),
		WriteEnabled: role.WriteEnabled,
		Description:  description,
	}

	// Optionally set AllowedIPs
	if len(role.AllowedIPs) > 0 {
		tokenRequest.AllowedIPs = role.AllowedIPs
	}

	// Detect token contract support
	contract, err := c.getTokenContract(ctx)
	if err != nil {
		return nil, err
	}

	// Abort if requesting version 2 on an unsupported server
	if role.Version == 2 && contract != newContract {
		return nil, errV2Unsupported
	}

	var secretData map[string]any

	switch role.Version {
	case 1:
		token, err := generateTokenKey()
		if err != nil {
			return nil, err
		}

		// we create v1 secret, set it now
		secretData = map[string]any{"token": token}

		if contract == oldContract {
			tokenRequest.Key = token
		} else {
			tokenRequest.Token = token
			tokenRequest.Version = 1
		}
	case 2:
		tokenRequest.Version = 2
	default:
		// This should be impossible given we control what can be set
		// this guard is to just avoid unexpected behaviour in the future
		return nil, errUnknownVersion
	}

	// Sent request to netbox
	tokenResponse := netboxTokenResponse{}
	err = c.doRequest(ctx, "POST", "/api/users/tokens/", &tokenRequest, &tokenResponse)
	if err != nil {
		if role.Version == 2 && errors.Is(err, errUnexpectedStatus) && strings.Contains(err.Error(), "API_TOKEN_PEPPERS") {
			return nil, errPepperNotConfigured
		}
		return nil, err
	}

	// Ensure we got an ID back
	if tokenResponse.ID == 0 {
		return nil, errors.New("netbox didn't return a token ID")
	}

	// Store the token ID
	secretInternal := map[string]any{"token_id": tokenResponse.ID}

	// v2 secret only exists in response from netbox
	if role.Version == 2 {
		secretData = map[string]any{"token": fmt.Sprintf("nbt_%s.%s", tokenResponse.Key, tokenResponse.Token)}
	}

	// build the secret to return to Vault
	resp := b.Secret(netboxTokenType).Response(secretData, secretInternal)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func generateTokenKey() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil // 20 bytes → 40 hex chars
}

var (
	errV2Unsupported       = errors.New("v2 token api unsupported")
	errUnknownVersion      = errors.New("unknown version")
	errPepperNotConfigured = errors.New("netbox api token peppers not configured, v2 token api unavailable")
)

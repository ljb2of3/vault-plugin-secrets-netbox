package secretengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleStoragePath = "role" // vault gives us a kv store, where are we storing our config?
)

// the json blob that will be written to vault to store our configuration
type roleConfig struct {
	Username     string        `json:"username"`
	WriteEnabled bool          `json:"write_enabled"`
	Description  string        `json:"description"`
	AllowedIPs   []string      `json:"allowed_ips"`
	TokenVersion int           `json:"token_version"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
}

func getRole(ctx context.Context, s logical.Storage, name string) (*roleConfig, error) {
	return nil, nil
}

func validateAllowedIP(input string) error {
	ip, network, err := net.ParseCIDR(input)

	if err != nil {
		return fmt.Errorf("%q: %w", input, err)
	}

	if !network.IP.Equal(ip) {
		return fmt.Errorf("%q: %w", input, errHostBitsSet)
	}

	return nil
}

var errHostBitsSet = errors.New("network contains host bits")

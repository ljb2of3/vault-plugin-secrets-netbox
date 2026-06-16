// Copyright Landy Bible <landy@ljb2of3.net> 2026
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	netbox "github.com/ljb2of3/vault-plugin-secrets-netbox"
)

func main() {
	// This is boilerplate code to wire up vault's auto generated mTLS config
	//   and provide the entrypoint that vault expects to talk to our plugin

	logger := hclog.New(&hclog.LoggerOptions{})

	apiClientMeta := &api.PluginAPIClientMeta{}

	flags := apiClientMeta.FlagSet()
	err := flags.Parse(os.Args[1:])

	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err = plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: netbox.Factory, // this is the link to our code in ../../backend.go
		TLSProviderFunc:    tlsProviderFunc,
	})

	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

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

	apiClientMeta := &api.PluginAPIClientMeta{}

	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: netbox.Factory, // this is the link to our code in ../../backend.go
		TLSProviderFunc:    tlsProviderFunc,
	})

	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

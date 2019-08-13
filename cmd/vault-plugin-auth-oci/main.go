package main

import (
	"os"

	log "github.com/hashicorp/go-hclog"

	ociauth "github.com/hashicorp/vault-plugin-auth-oci"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: ociauth.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.L().Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

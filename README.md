# Vault Plugin: Dynamic Netbox API Tokens

This a plugin for [HashiCorp Vault](https://developer.hashicorp.com/vault) that generates ephemeral [Netbox](https://github.com/netbox-community/netbox) API tokens.

## Getting Started

This is a Vault plugin and is meant to work with Vault. This guide assumes you have already installed Vault and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://developer.hashicorp.com/vault/tutorials/get-started/install-binary).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://developer.hashicorp.com/vault/docs/plugins).

### Installation

> [!IMPORTANT]
> You must have `plugin_directory` and `api_addr` set in your Vault configuration file.

1. Download the latest [release](https://github.com/ljb2of3/vault-plugin-secrets-netbox/releases) of the plugin, or compile it from source. If downloading, be sure to get the correct binary for your OS and CPU architecture.
2. Copy the binary into the `plugin_directory` on each of your vault servers.
3. Use [`vault plugin register`](https://developer.hashicorp.com/vault/docs/commands/plugin/register) to add your plugin to the catalog. For example:
```
vault plugin register \
    -command vault-plugin-secrets-netbox_0.3.1-rc1_linux_amd64 \
    -sha256 3b15f1f8cbf840e5f3f8eab0957d5857da3016cf39e8651b7f6faf7b4022263c \
    -version "v0.3.1-rc1" \
    secret \
    vault-plugin-secrets-netbox
```
4. Verify the plugin was registered by checking `vault plugin list`
```
$ vault plugin list
Name                                 Type        Version
----                                 ----        -------
alicloud                             auth        v0.23.1+builtin
approle                              auth        v2.0.2+builtin.vault
...                                  ...         ...
transit                              secret      v2.0.2+builtin.vault
vault-plugin-secrets-netbox          secret      v0.3.1-rc1
```
5. Enable the plugin
```
vault secrets enable \
    -path netbox \
    vault-plugin-secrets-netbox
```
5. Verify the plugin was enabled with `vault secrets list`
```
$ vault secrets list
Path               Type                           Accessor                                Description
----               ----                           --------                                -----------
agent-registry/    agent_registry                 agent-registry_d0853b2c                 agent registry
cubbyhole/         cubbyhole                      cubbyhole_e1c288da                      per-token private secret storage
identity/          identity                       identity_4103190e                       identity store
netbox/            vault-plugin-secrets-netbox    vault-plugin-secrets-netbox_31d45f2d    ephemeral netbox tokens
sys/               system                         system_81e72f2e                         system endpoints used for control, policy and debugging
```

### Configuration

Now that the plugin is installed, we can configure. You will need the address of a netbox server, and an existing API token that has rights to create and delete additional API tokens.

Here's a configuration example:

```
vault write netbox/config \
    url=https://demo.netbox.dev \
    token=dtagjHV3fZaISOqljy045aIccysURLwLBciVTTve
```

Additional options are available to either upload a custom CA certficate needed to communicate with netbox, or even disable TLS validation altogether, but you're not doing that production, right?

See `vault path-help netbox/config` for more information

### Create a Role

Before generating tokens, you must configure one or more roles. These will map to users on your netbox server that you would like to generate tokens for.

To create a role, write to `netbox/role/<name>`

At a minimum, you must supply a username. For example:

```
$ vault write netbox/role/test username=alice
```

Additional options are available to tune the ttl on generated tokens, set IPs allowed to use the tokens, or enable write access. Note that this plugin defaults to generating read-only tokens. See `vault path-help netbox/role/name` for more information.

To create a role to generate write enabled tokens:

```
$ vault write netbox/role/test-write username=bob write_enabled=true
```

### Generate Tokens

To get a netbox token, read from `netbox/creds/<role>`. For example:

```
$ vault read netbox/creds/test
Key                Value
---                -----
lease_id           netbox/creds/test/Ppvy6GmKSUVT3oW54LThqksw
lease_duration     768h
lease_renewable    false
token              4bab6bcb770901c468185d2910455ba4535cbe7f
```

## Note on AI use

These days software development with AI is the norm. That said...

> [!NOTE]
> The plugin code in this repo was artisanally hand-crafted by @ljb2of3

However, [Claude Code](https://claude.com/product/claude-code) was used in the following ways during development:
- To perform code reviews, and as a research assistant
- To design (not implement) test cases so no edge cases were forgotten
- Occasionally generated small code snippets (<10 lines) 
    - These were reviewed and placed into the codebase by hand
- Directly generated CI configurations which were reviewed by me prior to commit

## Addtional Information
For additional information, refer to the [offical vault docs](https://developer.hashicorp.com/vault/docs/plugins/register) or [offical netbox docs](https://netboxlabs.com/docs/netbox/).
# Vault Plugin: Dynamic NetBox API Tokens

This is a plugin for [HashiCorp Vault](https://developer.hashicorp.com/vault) that generates ephemeral [NetBox](https://github.com/netbox-community/netbox) API tokens.

## Zero to Token in 3 commands

```console
$ vault write netbox/config url=https://demo.netbox.dev token=dtagjHV3fZaISOqljy045aIccysURLwLBciVTTve
$ vault write netbox/role/test username=alice
$ vault read netbox/creds/test
Key                Value
---                -----
lease_id           netbox/creds/test/Ppvy6GmKSUVT3oW54LThqksw
lease_duration     768h
lease_renewable    false
token              4bab6bcb770901c468185d2910455ba4535cbe7f
```

## Getting Started

This is a Vault plugin and is meant to work with Vault. This guide assumes you have already installed Vault and have a basic understanding of how Vault works. Otherwise, first read this guide on how to [get started with Vault](https://developer.hashicorp.com/vault/tutorials/get-started/install-binary). To learn specifically about how plugins work, see documentation on [Vault plugins](https://developer.hashicorp.com/vault/docs/plugins).

### Installation

> [!IMPORTANT]
> You must have `plugin_directory` and `api_addr` set in your Vault configuration file.

1. Download the latest [release](https://github.com/ljb2of3/vault-plugin-secrets-netbox/releases) of the plugin, or [compile it from source](#building-from-source). If downloading, be sure to get the correct binary for your OS and CPU architecture — and optionally [verify the release](#verifying-releases) before trusting the binary.
2. Copy the binary into the `plugin_directory` on each of your Vault servers.
3. Use [`vault plugin register`](https://developer.hashicorp.com/vault/docs/commands/plugin/register) to add your plugin to the catalog. For example:
```bash
VERSION=0.4.0    # the release you downloaded
SHA256=...       # this binary's entry in the verified SHA256SUMS file

vault plugin register \
    -command "vault-plugin-secrets-netbox_${VERSION}_linux_amd64" \
    -sha256 "$SHA256" \
    -version "v$VERSION" \
    secret \
    vault-plugin-secrets-netbox
```
4. Verify the plugin was registered by checking `vault plugin list`
```console
$ vault plugin list
Name                                 Type        Version
----                                 ----        -------
alicloud                             auth        v0.23.1+builtin
approle                              auth        v2.0.2+builtin.vault
...                                  ...         ...
transit                              secret      v2.0.2+builtin.vault
vault-plugin-secrets-netbox          secret      v0.4.0
```
5. Enable the plugin
```bash
vault secrets enable \
    -path netbox \
    vault-plugin-secrets-netbox
```
6. Verify the plugin was enabled with `vault secrets list`
```console
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

Now that the plugin is installed, we can configure. You will need the address of a NetBox server, and an existing API token that has rights to create and delete additional API tokens.

Here's a configuration example:

```bash
vault write netbox/config \
    url=https://demo.netbox.dev \
    token=dtagjHV3fZaISOqljy045aIccysURLwLBciVTTve
```

Additional options are available to either upload a custom CA certificate needed to communicate with NetBox, or even disable TLS validation altogether, but you're not doing that in production, right?

See `vault path-help netbox/config` for more information

### Create a Role

Before generating tokens, you must configure one or more roles. These will map to users on your NetBox server that you would like to generate tokens for.

To create a role, write to `netbox/role/<name>`

At a minimum, you must supply a username. For example:

```bash
vault write netbox/role/test username=alice
```

Additional options are available to tune the ttl on generated tokens, set IPs allowed to use the tokens, or enable write access. Note that this plugin defaults to generating read-only tokens. See `vault path-help netbox/role/name` for more information.

To create a role to generate write enabled tokens:

```bash
vault write netbox/role/test-write username=bob write_enabled=true
```

### Generate Tokens

To get a NetBox token, read from `netbox/creds/<role>`. For example:

```console
$ vault read netbox/creds/test
Key                Value
---                -----
lease_id           netbox/creds/test/Ppvy6GmKSUVT3oW54LThqksw
lease_duration     768h
lease_renewable    false
token              4bab6bcb770901c468185d2910455ba4535cbe7f
```

## Verifying Releases

Release binaries are signed with [cosign](https://github.com/sigstore/cosign) using keyless
signing, and the checksums are published as `SHA256SUMS`. Before trusting a binary you can
verify it genuinely came from this repo's release pipeline.

Download the binary you want along with `SHA256SUMS`, `SHA256SUMS.pem`, and `SHA256SUMS.sig`
from the [releases page](https://github.com/ljb2of3/vault-plugin-secrets-netbox/releases),
then verify the signature on the checksums:

```bash
VERSION=0.4.0    # the release you downloaded

cosign verify-blob \
    --certificate "vault-plugin-secrets-netbox_${VERSION}_SHA256SUMS.pem" \
    --signature "vault-plugin-secrets-netbox_${VERSION}_SHA256SUMS.sig" \
    --certificate-identity "https://github.com/ljb2of3/vault-plugin-secrets-netbox/.github/workflows/release.yml@refs/tags/v${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "vault-plugin-secrets-netbox_${VERSION}_SHA256SUMS"
```

A successful check prints `Verified OK`. Once the checksums are trusted, the `-sha256` value
used in the register step above is simply your binary's entry in the verified `SHA256SUMS` file.

Each binary also ships with a [Syft](https://github.com/anchore/syft) SBOM (`*.sbom.json`) if
you want to inspect or scan its dependencies.

## Building from Source

If you'd rather build the plugin yourself instead of downloading a release:

```bash
go build -o vault-plugin-secrets-netbox ./cmd/vault-plugin-secrets-netbox
```

This drops the plugin binary in the current directory, ready to copy into your
`plugin_directory`. Note that a plain `go build` self-reports a development version
(`v0.0.0-dev`) in `vault plugin list`; release builds have the real version injected at build
time via [GoReleaser](https://goreleaser.com) (see `.goreleaser.yml`).

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

## Additional Information
For additional information, refer to the official [Vault docs](https://developer.hashicorp.com/vault/docs/plugins/register) or [NetBox docs](https://netboxlabs.com/docs/netbox/).

## License
This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE) for the full text.
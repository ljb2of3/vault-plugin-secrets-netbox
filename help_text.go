package secretengine

// <mount>/
const rootHelp = `
The Netbox secrets backend dynamically generates API tokens. 
Use config/ to set the netbox url and admin credentials with permissions to generate tokens.
Then create a role/<name> to configure a username to generate a token for.
Call creds/<role> to generate a token.`

// <mount>/config
const pathConfigHelpSynopsis = `
Configure the Netbox backend`

const pathConfigHelpDescription = `
The Netbox secret backend requires a Netbox server URL
and credentials for creating and destroying API tokens`

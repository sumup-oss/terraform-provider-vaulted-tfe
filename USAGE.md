# Usage

## Prerequisites

The following apply here as well.

https://github.com/sumup-oss/vaulted#prerequisites

## Simple integration approach

1. Generate RSA keypair by following https://github.com/sumup-oss/vaulted#setup
1. Specify `provider` by following [provider.tf](./examples/provider/provider.tf)
1. Add `vaulted-tfe_variable` resources
1. `terraform plan`
1. `terraform apply`
1. :tada:

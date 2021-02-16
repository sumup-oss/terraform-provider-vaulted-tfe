# Frequently asked questions

## Should I use this provider or official TFE provider? (https://registry.terraform.io/providers/hashicorp/tfe/latest/)

This provider is complimentary to the official TFE provider.
You would want to use `vaulted-tfe` **only** to provision **sensitive** variables.

So practical example - you want to provision a Postgres database. You have `address` (host+port), `username`, `password`.

You can provision `address` and `username` with the official TFE provider, since they're safe to commit in SCM as plaintext.
However, you would want to provision `password` via `vaulted-tfe` provider, since they're **not safe** to commit in SCM.

## The terraform secrets I put are encrypted in the git repository, but what about terraform state - local and external? Are they leaking plaintext somewhere?

`terraform-provider-vaulted-tfe` takes extreme care never to put into `stdout` and `terraform.tfstate` neither in local state nor in remote, any plaintext values.

Your secrets are only put (`set` in terraform API terms) into terraform state with their encrypted presentation.

**When comparing terraform resource values with external Terraform Cloud to synchronize state, they're never put into decrypted (plaintext) state.
Only in memory they're temporarily plaintext.**

## I've applied my secrets via `terraform`, but someone **deleted** them from Terraform Cloud. What now?

When you run `terraform plan` or `terraform apply` your `vaulted-tfe_variable` resources will
verify that their decrypted content is present in the external Terraform Cloud.
If they're missing, it'll show up as `deleted` resources in terraform diff.

Once you run `terraform apply` they're going to be present once again.

## I've applied my secrets via `terraform`, but someone **modified** them from Terraform Cloud. What now?

Due to how `sensitive=true` works in Terraform Cloud API for variables, 
if you've provisioned these variables you won't see a difference in your `terraform plan`. 
(ref: https://www.terraform.io/docs/cloud/workspaces/variables.html#sensitive-values).

You can either:
* provision variables with `sensitive=false` to make sure terraform will always notice "manual" changes (not recommended).
* manually taint the resource(s) `terraform taint vaulted-tfe_variable.myvar` and `terraform apply`.

## I've rotated my secrets via `vaulted` and now want to `terraform apply` them. What will happen?

When you run `terraform plan` you're going to see terraform state difference.

`terraform apply` and the state will be updated. The external Terraform Cloud varaible will remain the same.

## I've rekeyed my secrets via `vaulted` and now want to `terraform apply` them. What will happen?

When you run `terraform plan` you're going to see terraform state difference.

`terraform apply` and the state will be updated. The external Terraform Cloud variable  will remain the same.
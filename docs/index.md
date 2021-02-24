---
page_title: "vaultedtfe Provider"
subcategory: ""
description: |-
  
---

# vaultedtfe Provider



## Example Usage

```terraform
provider "vaultedtfe" {
  # example configuration here
}
```

## Schema

### Required

- **token** (String) The token used to authenticate with Terraform Cloud/Enterprise.

### Optional

- **hostname** (String) The Terraform Enterprise hostname to connect to. Defaults to app.terraform.io.
- **private_key_content** (String) Content of private key used to decrypt `vaultedtfe_variable` resources. This setting has higher priority than `private_key_path`.
- **private_key_path** (String) Path to private key used to decrypt `vaultedtfe_variable` resources. This setting has lower priority than `private_key_content`.
- **protocol** (String) Protocol to use when connecting to specified `hostname` Terraform Enterprise. Defaults to https
- **ssl_skip_verify** (Boolean) Whether or not to skip certificate verifications.

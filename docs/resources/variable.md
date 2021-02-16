---
page_title: "vaultedtfe_variable Resource - terraform-provider-vaultedtfe"
subcategory: ""
description: |-
  
---

# Resource `vaultedtfe_variable`





## Schema

### Required

- **category** (String)
- **key** (String)
- **value** (String, Sensitive) Encrypted value by github.com/sumup-oss/vaulted
- **workspace_id** (String)

### Optional

- **description** (String)
- **hcl** (Boolean)
- **id** (String) The ID of this resource.
- **sensitive** (Boolean)



# terraform-provider-vaultedtfe

![Build status](https://github.com/sumup-oss/terraform-provider-vaultedtfe/workflows/Go/badge.svg)

[![Go Report Card](https://goreportcard.com/badge/github.com/sumup-oss/terraform-provider-vaultedtfe)](https://goreportcard.com/report/github.com/sumup-oss/terraform-provider-vaultedtfe)

A terraform provider that utilizes https://github.com/sumup-oss/vaulted to provide
https://github.com/hashicorp/terraform for https://app.terraform.io/ (Terraform Cloud/Enterprise) encrypted variables via
`resource.vaultedtfe_variable` that:

* are **never** stored as plaintext in your terraform state.
* are **never** logged in stdout as plaintext.
* can be **safely** stored in SCM such as Git in their encrypted payload format produced by https://github.com/sumup-oss/vaulted .

Tested and used with "public" Terraform Cloud.

## Why should I use this?

At SumUp we're adopting Terraform Cloud with multiple workspaces as our
preferred terraform executor and remote state manager. 

We're already using https://github.com/sumup-oss/terraform-provider-vaulted/ 
 to allow **everyone** inside the organization to provision secrets, 
store them in SCM and CI to provision them.

This enables us to completely shift-left in terms of responsibilities.

However, while moving to Terraform Cloud, we've noticed that we were
 lacking a way to provision the Terraform Cloud workspace variables and 
store them in SCM.

## Installation

https://registry.terraform.io/providers/sumup-oss/vaultedtfe/latest

## [Usage](./USAGE.md)

## [Contributing](./CONTRIBUTING.md)

## [FAQ](./FAQ.md)

## About SumUp

[SumUp](https://sumup.com) is a mobile-point of sale provider.

It is our mission to make easy and fast card payments a reality across the *entire* world.

You can pay with SumUp in more than 30 countries, already.

Our engineers work in Berlin, Cologne, Sofia and Sāo Paulo.

They write code in JavaScript, Swift, Ruby, Go, Java, Erlang, Elixir and more.

Want to come work with us? [Head to our careers page](https://sumup.com/careers) to find out more.
## Unreleased

## 0.14.1
### September 5, 2023

IMPROVEMENTS:
* Update dependencies:
  * github.com/hashicorp/vault/api v1.9.1 -> v1.9.2
  * github.com/hashicorp/vault/sdk v0.9.0 -> v0.9.2

## 0.14.0

* Add display attributes for OpenAPI OperationID's [GH-29](https://github.com/hashicorp/vault-plugin-auth-oci/pull/29)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.1 [GH-31](https://github.com/hashicorp/vault-plugin-auth-oci/pull/31)

## 0.13.1

CHANGES:
* Repond with a 400 instead of 401 to login errors. [GH-27](https://github.com/hashicorp/vault-plugin-auth-oci/pull/27)

IMPROVEMENTS:

* Return success message when writing role [GH-27](https://github.com/hashicorp/vault-plugin-auth-oci/pull/27)
* Return error messages when failing to login [GH-27](https://github.com/hashicorp/vault-plugin-auth-oci/pull/27)
* enable plugin multiplexing [GH-25](https://github.com/hashicorp/vault-plugin-auth-oci/pull/25)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.0
  * `github.com/hashicorp/vault/sdk` v0.8.1
